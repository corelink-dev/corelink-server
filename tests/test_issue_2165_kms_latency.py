from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import issue_2165_kms_latency as latency


ACCOUNT = "123456789012"
CF_ACCOUNT = "51284495e71acdb5a7677e7383ab026b"
DATABASE = "d" * 32
KEY = f"arn:aws:kms:us-east-1:{ACCOUNT}:key/" + "e" * 36
ROLE = f"arn:aws:iam::{ACCOUNT}:role/kms-custodian"
CALLER = f"arn:aws:sts::{ACCOUNT}:assumed-role/kms-custodian/session"
TENANTS = ["00000000-0000-4000-8000-000000000001", "00000000-0000-4000-8000-000000000002"]
RUN_ID = "1234567"
START = 1_790_784_000_000
END = START + 3_600_000
ENV = {
    "B083_AWS_ACCOUNT_ID": ACCOUNT,
    "B083_AWS_REGION": "us-east-1",
    "B083_KMS_KEY_ARN": KEY,
    "B083_AWS_CUSTODIAN_ROLE_ARN": ROLE,
    "B083_CF_ACCOUNT_ID": CF_ACCOUNT,
    "B083_D1_DATABASE_ID": DATABASE,
    "B083_D1_REGION": "iad",
    "GITHUB_RUN_ID": RUN_ID,
}


def utc(ms: int) -> str:
    return datetime.fromtimestamp(ms / 1000, timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def digest(value) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(raw).hexdigest()


def manifest() -> dict:
    return {
        "schema": "corelink-issue-2165-kms-runtime-v1",
        "environment": "b083-kms-lifecycle",
        "aws": {"account_id": ACCOUNT, "region": "us-east-1", "cmk_provider": "aws", "cmk_arn": KEY, "custodian_role_arn": ROLE},
        "cloudflare": {"account_alias": "cf5128", "account_id": CF_ACCOUNT, "d1": {"database_id": DATABASE, "region": "iad"}},
        "disposable_tenants": TENANTS,
        "lifecycle_window": {"started_at_ms": START, "ended_at_ms": END},
    }


def row(tenant: str, action: str, epoch: int, completed: int) -> dict:
    return {
        "token": f"row-token-{tenant[-1]}-{epoch}",
        "tenant_id": tenant,
        "epoch": epoch,
        "action": action,
        "cmk_provider": "aws",
        "cmk_key_id": KEY,
        "outcome": "completed",
        "completed_at_ms": completed,
    }


def d1_result(rows: list[dict], action: str) -> dict:
    sql = (
        "SELECT token, tenant_id, epoch, action, cmk_provider, cmk_key_id, outcome, completed_at_ms "
        "FROM byok_control_outcome WHERE tenant_id IN (?, ?) AND cmk_provider = ? AND cmk_key_id = ? "
        "AND action = ? AND outcome = 'completed' AND completed_at_ms >= ? AND completed_at_ms <= ? "
        "ORDER BY completed_at_ms, tenant_id"
    )
    params = [*TENANTS, "aws", KEY, action, START, END]
    token_hash = hashlib.sha256("\n".join(sorted(item["token"] for item in rows)).encode()).hexdigest()
    return {
        "rows": rows,
        "d1_source": {
            "method": "parameterized-select-post",
            "account_alias": "cf5128",
            "endpoint": f"https://api.cloudflare.com/client/v4/accounts/{CF_ACCOUNT}/d1/database/{DATABASE}/query",
            "account_id": CF_ACCOUNT,
            "database_id": DATABASE,
            "d1_region": "iad",
            "query_sha256": digest({"sql": sql, "params": params}),
            "response_sha256": hashlib.sha256(f"full-{action}".encode()).hexdigest(),
            "selected_rows_sha256": digest(rows),
            "selected_token_set_sha256": token_hash,
            "cf_token_identity_sha256": hashlib.sha256(b"verified-cf-token-identity").hexdigest(),
            "read_only_metadata": {"changed_db": False, "rows_written": 0, "changes": 0},
            "observed_at_utc": utc(START + 500),
        },
    }


def make_evidence(*, slow: bool = False) -> tuple[dict, dict]:
    cycles, events = [], []
    grant_ids = [f"grant-{i}" for i in range(11)]
    for cycle_no in range(1, 11):
        base = START + cycle_no * (320_000 if slow else 120_000)
        revoke_started, revoke_ended = base, base + 200
        revoke_event_ms = base + 100
        if slow:
            degrade_at = base + 300_101
            restore_started, restore_ended = base + 300_200, base + 300_300
            create_event_ms = base + 300_250
            restore_at = base + 300_400
        else:
            degrade_at = base + 500
            restore_started, restore_ended = base + 1_000, base + 1_200
            create_event_ms = base + 1_100
            restore_at = base + 1_500
        degrade_rows = [row(tenant, "degrade", 2 * cycle_no - 1, degrade_at) for tenant in TENANTS]
        restore_rows = [row(tenant, "restore", 2 * cycle_no, restore_at) for tenant in TENANTS]
        cycles.append({
            "cycle": cycle_no,
            "cycle_started_at_utc": utc(base - 100),
            "revoke": {"grant_id": grant_ids[cycle_no - 1], "started_at_utc": utc(revoke_started), "ended_at_utc": utc(revoke_ended), "provider_readback": "absent"},
            "degrade_rows": d1_result(degrade_rows, "degrade"),
            "restore": {"grant_id": grant_ids[cycle_no], "started_at_utc": utc(restore_started), "ended_at_utc": utc(restore_ended), "provider_readback": "exact"},
            "restore_rows": d1_result(restore_rows, "restore"),
        })
        for name, gid, instant in (("RevokeGrant", grant_ids[cycle_no - 1], revoke_event_ms), ("CreateGrant", grant_ids[cycle_no], create_event_ms)):
            inner = {
                "eventID": f"event-{cycle_no}-{name}",
                "eventName": name,
                "eventTime": utc(instant),
                "eventSource": "kms.amazonaws.com",
                "awsRegion": "us-east-1",
                "recipientAccountId": ACCOUNT,
                "userIdentity": {
                    "type": "AssumedRole",
                    "accountId": ACCOUNT,
                    "sessionContext": {"sessionIssuer": {"arn": ROLE}},
                },
                "requestParameters": {"keyId": KEY, "grantId": gid} if name == "RevokeGrant" else {"keyId": KEY, "name": f"issue-2165-{RUN_ID}"},
            }
            if name == "CreateGrant":
                inner["responseElements"] = {"grantId": gid}
            events.append({"EventId": inner["eventID"], "EventName": name, "EventSource": "kms.amazonaws.com", "EventTime": utc(instant), "CloudTrailEvent": json.dumps(inner, separators=(",", ":"))})
    bundle = {
        "schema": "corelink.issue-2165-kms-cycle-bundle.v1",
        "run_id": RUN_ID,
        "window": {"started_at_ms": START, "ended_at_ms": END},
        "target": {"cmk_provider": "aws", "cmk_key_arn": KEY, "redacted_tenant_slots": ["tenant_a", "tenant_b"], "tenant_ids": TENANTS},
        "grant_ids": grant_ids,
        "final_grant_id": grant_ids[-1],
        "cycles": cycles,
        "d1_source_attestation": {
            "provider": "cloudflare-d1",
            "method": "parameterized-select-post",
            "account_alias": "cf5128",
            "account_id": CF_ACCOUNT,
            "database_id": DATABASE,
            "d1_region": "iad",
            "changed_db": False,
            "rows_written": 0,
            "changes": 0,
        },
    }
    cloudtrail = {
        "schema": "corelink-issue-2165-cloudtrail-latency-v1",
        "run_id": RUN_ID,
        "source": {"method": "LookupEvents", "caller_arn": CALLER, "account_id": ACCOUNT, "region": "us-east-1", "window_start_utc": utc(START), "window_end_utc": utc(END), "response_sha256": digest(events)},
        "events": events,
    }
    return bundle, cloudtrail


class KmsLatencyContract(unittest.TestCase):
    def test_builds_exact_redacted_twenty_by_twenty_sample_artifact(self):
        bundle, cloudtrail = make_evidence()
        output = latency.verify(manifest(), bundle, cloudtrail, ENV)
        self.assertEqual(output["directions"]["revoke_degrade"]["n"], 20)
        self.assertEqual(output["directions"]["restore_active"]["n"], 20)
        self.assertEqual(output["directions"]["revoke_degrade"]["p99_ms"], 400)
        rendered = json.dumps(output)
        for secretish in (KEY, ROLE, TENANTS[0], "grant-1", "row-token"):
            self.assertNotIn(secretish, rendered)
        self.assertNotIn("audit://", rendered)

    def test_rejects_wrong_protected_identity_run_and_window(self):
        bundle, ct = make_evidence()
        with self.assertRaises(latency.LatencyError):
            latency.verify(manifest(), bundle, ct, {**ENV, "B083_KMS_KEY_ARN": "wrong"})
        bundle, ct = make_evidence()
        bundle["run_id"] = "7654321"
        with self.assertRaises(latency.LatencyError):
            latency.verify(manifest(), bundle, ct, ENV)
        bundle, ct = make_evidence()
        bundle["window"]["ended_at_ms"] += 1
        with self.assertRaises(latency.LatencyError):
            latency.verify(manifest(), bundle, ct, ENV)

    def test_rejects_untrusted_source_role_or_d1_write_claim(self):
        bundle, ct = make_evidence()
        ct["source"]["caller_arn"] = "arn:aws:sts::999999999999:assumed-role/kms-custodian/session"
        with self.assertRaises(latency.LatencyError):
            latency.verify(manifest(), bundle, ct, ENV)
        bundle, ct = make_evidence()
        bundle["cycles"][0]["degrade_rows"]["d1_source"]["read_only_metadata"]["rows_written"] = 1
        with self.assertRaises(latency.LatencyError):
            latency.verify(manifest(), bundle, ct, ENV)

    def test_rejects_outer_inner_event_id_and_digest_mismatch(self):
        bundle, ct = make_evidence()
        ct["events"][0]["EventId"] = "substituted"
        ct["source"]["response_sha256"] = digest(ct["events"])
        with self.assertRaisesRegex(latency.LatencyError, "EventId"):
            latency.verify(manifest(), bundle, ct, ENV)
        bundle, ct = make_evidence()
        ct["source"]["response_sha256"] = "0" * 64
        with self.assertRaisesRegex(latency.LatencyError, "digest"):
            latency.verify(manifest(), bundle, ct, ENV)

    def test_rejects_missing_duplicate_cross_slot_and_wrong_key_rows(self):
        mutations = []
        bundle, ct = make_evidence()
        del bundle["cycles"][0]["degrade_rows"]["rows"][0]
        mutations.append(bundle)
        bundle, ct = make_evidence()
        bundle["cycles"][0]["degrade_rows"]["rows"][1]["tenant_id"] = TENANTS[0]
        bundle["cycles"][0]["degrade_rows"]["d1_source"]["selected_rows_sha256"] = digest(bundle["cycles"][0]["degrade_rows"]["rows"])
        mutations.append(bundle)
        bundle, ct = make_evidence()
        bundle["cycles"][0]["restore_rows"]["rows"][0]["cmk_key_id"] = "wrong-key"
        bundle["cycles"][0]["restore_rows"]["d1_source"]["selected_rows_sha256"] = digest(bundle["cycles"][0]["restore_rows"]["rows"])
        mutations.append(bundle)
        for mutated in mutations:
            with self.subTest(cycles=len(mutated["cycles"])):
                with self.assertRaises(latency.LatencyError):
                    latency.verify(manifest(), mutated, ct, ENV)

    def test_rejects_duplicate_event_ids_grants_epochs_and_missing_cycles(self):
        bundle, ct = make_evidence()
        ct["events"][1]["EventId"] = ct["events"][0]["EventId"]
        ct["events"][1]["CloudTrailEvent"] = ct["events"][0]["CloudTrailEvent"]
        ct["source"]["response_sha256"] = digest(ct["events"])
        with self.assertRaises(latency.LatencyError):
            latency.verify(manifest(), bundle, ct, ENV)
        bundle, ct = make_evidence()
        bundle["cycles"][1]["cycle"] = 1
        with self.assertRaises(latency.LatencyError):
            latency.verify(manifest(), bundle, ct, ENV)
        bundle, ct = make_evidence()
        bundle["cycles"][1]["degrade_rows"]["rows"][0]["epoch"] = bundle["cycles"][0]["degrade_rows"]["rows"][0]["epoch"]
        bundle["cycles"][1]["degrade_rows"]["d1_source"]["selected_rows_sha256"] = digest(bundle["cycles"][1]["degrade_rows"]["rows"])
        with self.assertRaises(latency.LatencyError):
            latency.verify(manifest(), bundle, ct, ENV)

    def test_rejects_negative_and_over_limit_p99_latency(self):
        bundle, ct = make_evidence()
        row0 = bundle["cycles"][0]["degrade_rows"]["rows"][0]
        row0["completed_at_ms"] = START + 50
        bundle["cycles"][0]["degrade_rows"]["d1_source"]["selected_rows_sha256"] = digest(bundle["cycles"][0]["degrade_rows"]["rows"])
        with self.assertRaises(latency.LatencyError):
            latency.verify(manifest(), bundle, ct, ENV)
        bundle, ct = make_evidence(slow=True)
        with self.assertRaisesRegex(latency.LatencyError, "p99"):
            latency.verify(manifest(), bundle, ct, ENV)

    def test_cli_writes_private_artifact_and_refuses_existing_output(self):
        bundle, ct = make_evidence()
        wrapper = {"schema": "corelink.issue-2165-kms-latency-input.v1", "run_id": RUN_ID, "cycle_bundle": bundle, "cloudtrail": ct}
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            paths = [root / "manifest.json", root / "input.json", root / "lifecycle-samples.json"]
            paths[0].write_text(json.dumps(manifest()), encoding="utf-8")
            paths[1].write_text(json.dumps(wrapper), encoding="utf-8")
            paths[0].chmod(0o600)
            paths[1].chmod(0o600)
            env = {**os.environ, **ENV}
            args = [sys.executable, str(ROOT / "scripts/issue_2165_kms_latency.py"), "--manifest", str(paths[0]), "--input", str(paths[1]), "--output", str(paths[2])]
            result = subprocess.run(args, env=env, capture_output=True, text=True, check=False)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(stat.S_IMODE(paths[2].stat().st_mode), 0o600)
            output = json.loads(paths[2].read_text(encoding="utf-8"))
            self.assertNotIn(KEY, json.dumps(output))
            source = output["audit_source_receipt"]
            self.assertEqual(source["step"], "revoke_restore")
            self.assertEqual(source["source"]["kind"], "cloudtrail")
            self.assertIn("cloudtrail:event-", source["source"]["event_ref"])
            self.assertEqual(source["source"]["digest"], output["artifact_sha256"])
            self.assertRegex(source["occurred_at_utc"], r"Z$")
            for direction in output["directions"].values():
                self.assertEqual(len(direction["samples"]), 20)
                self.assertTrue(all(row["cloudtrail_event_id"].startswith("event-") for row in direction["samples"]))
                self.assertTrue(all(row["transition_completed_at_utc"].endswith("Z") for row in direction["samples"]))
            second = subprocess.run(args, env=env, capture_output=True, text=True, check=False)
            self.assertNotEqual(second.returncode, 0)


if __name__ == "__main__":
    unittest.main()
