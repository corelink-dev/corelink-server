#!/usr/bin/env python3
"""Hosted-only adversarial tests for the B-072 D1 and operator fences."""
from __future__ import annotations

import sqlite3
import hashlib
import tempfile
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from threading import Barrier
import unittest
from pathlib import Path
from unittest.mock import patch

import issue_1652_b072_operator as operator

from issue_1652_b072_operator import (
    MIGRATION,
    OperatorError,
    auth_values,
    approved_environment_review,
    require_configured_independent_approver,
    safe_error,
    verify_1700_receipt,
    execute,
    recover,
)


NONCE = "n" * 48
SHA = "0123456789abcdef0123456789abcdef01234567"
RECEIVER = "staging-version-123"
ROOT = Path(__file__).resolve().parents[1]
RUN_ID = 4242
ROOT_VERSION = "root-active-v1"
RECEIVER_VERSION = "receiver-disabled-v1"
CANDIDATE_VERSION = "receiver-candidate-v2"
RECEIVER_WORKER = operator.RECEIVER_WORKER
DRILL_AT = 1_800_001_800_000


class FakeGitHub:
    def __init__(self, *, sha: str = SHA):
        self.sha = sha
        self.events: list[str] = []

    def main_sha(self) -> str:
        self.events.append("github-main-sha")
        return self.sha

    def environment(self) -> dict:
        self.events.append("github-staging-environment")
        return {"protection_rules": [{"type": "required_reviewers", "reviewers": [
            {"type": "User", "reviewer": {"id": 7, "login": "independent-reviewer"}},
            {"type": "User", "reviewer": {"id": 8, "login": "operator"}},
        ]}]}

    def approval(self, run_id: int, actor: str) -> dict:
        self.events.append("github-run-approval")
        return approved_environment_review([{"state": "approved",
            "user": {"id": 7, "login": "independent-reviewer"},
            "comment": "approved", "environments": [{"name": "staging"}]}],
            run_id=run_id, actor=actor,
            observed_at=datetime(2026, 9, 30, tzinfo=timezone.utc))

    def issue_1700_pass(self, run_id: int, sha: str, verification_sha: str) -> dict:
        self.events.append("github-1700-pass")
        if run_id != 1700 or sha != SHA or verification_sha != "f" * 40:
            raise OperatorError("fake #1700 receipt identity mismatch")
        return {"run_id": run_id, "outcome": "pass", "contract": "issue-1700-existing-runtime-completion-v1"}


class FakeCloudflare:
    """Bounded API-shape fake that records mutation ordering and D1 evidence."""

    def __init__(self, *, fail_activation: bool = False, fail_revocation: bool = False,
                 fail_disarm: bool = False, fail_authorization_readback: bool = False):
        self._request = lambda *args, **kwargs: None
        self.events: list[str] = []
        self.schedules: list[str] = []
        self.active_receiver = RECEIVER_VERSION
        self.authorization: dict | None = None
        self.activation: dict | None = None
        self.revocation: dict | None = None
        self.fail_activation = fail_activation
        self.fail_revocation = fail_revocation
        self.fail_disarm = fail_disarm
        self.fail_authorization_readback = fail_authorization_readback
        self.routes: list[dict] = []
        drill_id = f"SP-{DRILL_AT}"
        correlation = f"PAT-CORRELATION-ID-001:{drill_id}"
        self.receipts = [{"drill_id": drill_id, "scheduled_at_ms": DRILL_AT,
            "correlation_id": correlation, "provider_mode": "provider_deferred",
            "outcome": "provider_deferred", "scheduler_worker_revision": SHA,
            "serving_sha": SHA, "receiver_worker_revision": CANDIDATE_VERSION,
            "receiver_result": "persisted_provider_deferred"}]
        self.audit = [{"event_type": "provider_deferred", "correlation_id": correlation}]
        self.ingresses = [{"drill_id": drill_id, "scheduled_at_ms": DRILL_AT,
            "serving_sha": SHA, "receiver_worker_revision": CANDIDATE_VERSION, "ingress_count": 1}]
        self.drills = [{"drill_id": drill_id, "scheduled_at_ms": DRILL_AT, "correlation_id": correlation}]
        self.claim_rows: list[dict] = []

    def call(self, method: str, path: str, body: dict | None = None) -> dict:
        if path.endswith("/schedules"):
            if method == "PUT":
                crons = [item["cron"] for item in body["schedules"]]
                self.events.append("schedule-arm" if crons else "schedule-disarm")
                if not crons and self.fail_disarm:
                    raise OperatorError("fake schedule disarm failure")
                self.schedules = crons
                return {"success": True, "result": {}}
            return {"success": True, "result": {"schedules": [{"cron": cron} for cron in self.schedules]}}
        if path.endswith("/deployments") and method == "POST":
            version = body["versions"][0]["version_id"]
            self.events.append(f"deploy:{version}")
            if RECEIVER_WORKER in path:
                self.active_receiver = version
            return {"success": True, "result": {}}
        if path.endswith("/deployments") and method == "GET":
            version = self.active_receiver if RECEIVER_WORKER in path else ROOT_VERSION
            self.events.append(f"read-active:{version}")
            return {"success": True, "result": [{"versions": [{"version_id": version, "percentage": 100}]}]}
        if path.endswith("/subdomain"):
            return {"success": True, "result": {"enabled": False, "previews_enabled": False}}
        raise AssertionError(f"unexpected Cloudflare request: {method} {path}")

    def d1(self, database_id: str, token: str, sql: str, params: list | None = None) -> list[dict]:
        self.events.append("d1:" + sql.split()[0:3].__str__())
        params = params or []
        if "INSERT INTO b072_one_shot_authorization" in sql:
            self.authorization = {"issue_id": 1652, "serving_sha": params[0], "approval_nonce": params[1],
                "receiver_worker_revision": params[2], "approved_reviewer": params[3], "approved_run_id": params[4],
                "authorized_at_ms": params[5], "starts_at_ms": params[6], "ends_at_ms": params[7]}
            self.events.append("authorization-write")
            return []
        if "FROM b072_one_shot_authorization" in sql:
            if self.fail_authorization_readback:
                self.fail_authorization_readback = False
                raise OperatorError("fake authorization readback failure")
            return [self.authorization] if self.authorization else []
        if "INSERT INTO b072_one_shot_activation" in sql:
            self.events.append("activation-write")
            if self.fail_activation:
                raise OperatorError("fake activation write failure")
            self.activation = {"approval_nonce": params[0], "receiver_worker_revision": params[1],
                               "armed_cron": params[2]}
            return []
        if "FROM b072_one_shot_activation" in sql:
            return [self.activation] if self.activation else []
        if "INSERT OR IGNORE INTO b072_one_shot_revocation" in sql:
            self.events.append("revocation-write")
            if self.fail_revocation:
                raise OperatorError("fake revocation write failure")
            self.revocation = {"approval_nonce": params[0], "revoked_at_ms": params[1], "reason": params[2]}
            return []
        if "FROM b072_one_shot_revocation" in sql:
            return [self.revocation] if self.revocation else []
        if "FROM b072_one_shot_claim" in sql and "SELECT drill_id, scheduled_at_ms FROM" in sql:
            return [{"drill_id": f"SP-{DRILL_AT}", "scheduled_at_ms": DRILL_AT}]
        if "FROM b072_one_shot_claim" in sql:
            return self.claim_rows
        if "FROM synthetic_page_provider_receipts" in sql:
            return self.receipts
        if "FROM synthetic_page_provider_audit_events" in sql:
            return self.audit
        if "FROM b072_one_shot_ingress" in sql:
            return self.ingresses
        if "FROM synthetic_page_drills_b072" in sql:
            return self.drills
        raise AssertionError(f"unexpected D1 query: {sql}")

    def zone_route_inventory(self) -> list[dict]:
        return self.routes


def execution_env() -> dict[str, str]:
    return {
        "GITHUB_SHA": SHA, "GITHUB_REPOSITORY": "HuGR-dev/corelink-server",
        "GITHUB_REPOSITORY_ID": "1232040291", "GITHUB_REF": "refs/heads/main",
        "GITHUB_RUN_ID": str(RUN_ID), "GITHUB_ACTOR": "operator", "B072_ISSUE_1700_SHA": "f" * 40,
        "B072_STAGING_CF_ACCOUNT_ID": "6a1fc1c626fc2628823e60b9db01f5cd",
        "B072_STAGING_D1_DATABASE_ID": "d72a6b39-6a48-4338-bfda-1111dda98604",
        "B072_STAGING_CF_WORKERS_TOKEN": "fake-workers-token",
        "B072_STAGING_D1_WRITE_TOKEN": "fake-d1-token",
        "B072_STAGING_CF_ROUTE_READ_TOKEN": "fake-route-token",
    }


def database() -> sqlite3.Connection:
    connection = sqlite3.connect(":memory:")
    connection.execute("PRAGMA foreign_keys = ON")
    root = ROOT
    connection.executescript((root / "migrations/d1/0043_synthetic_page_drills.sql").read_text(encoding="utf-8"))
    connection.execute(
        "INSERT INTO synthetic_page_drills "
        "(drill_id, region, severity, emit_ts_ms, outcome, correlation_id) "
        "VALUES (?, 'americas', 'sev2_synthetic', ?, 'unacked', ?)",
        ("SP-1785844800000", 1_785_844_800_000, "PAT-CORRELATION-ID-001:SP-1785844800000"),
    )
    connection.executescript((root / "migrations/d1/0116_synthetic_page_delivery_lifecycle.sql").read_text(encoding="utf-8"))
    connection.executescript((root / "migrations/d1/0150_b072_provider_deferred_receipts.sql").read_text(encoding="utf-8"))
    connection.executescript((ROOT / MIGRATION).read_text(encoding="utf-8"))
    assert connection.execute("SELECT COUNT(*) FROM synthetic_page_drills").fetchone()[0] == 1
    assert connection.execute("SELECT COUNT(*) FROM synthetic_page_drills_b072").fetchone()[0] == 1
    return connection


def authorize(connection: sqlite3.Connection) -> None:
    connection.execute(
        "INSERT INTO b072_one_shot_authorization VALUES(1,1652,?,?,?,?,?,?,?,?)",
        (SHA, NONCE, RECEIVER, "independent-reviewer", 42, 1_000_000, 2_500_000, 4_000_000),
    )


def activate(connection: sqlite3.Connection) -> None:
    connection.execute(
        "INSERT INTO b072_one_shot_activation VALUES(1,?,?,?,?,?)",
        (NONCE, RECEIVER, "* * * * *", 1_200_000, 1_200_001),
    )


class MigrationFenceTests(unittest.TestCase):
    def test_migration_is_repeatable_and_singleton_rows_are_immutable(self) -> None:
        db = database()
        db.executescript((ROOT / MIGRATION).read_text(encoding="utf-8"))
        db.execute("INSERT INTO b072_one_shot_migration_receipt VALUES(1,?,?,?)",
                   (MIGRATION.name, hashlib.sha256((ROOT / MIGRATION).read_bytes()).hexdigest(), 1_000_000))
        with self.assertRaises(sqlite3.IntegrityError):
            db.execute("UPDATE b072_one_shot_migration_receipt SET applied_at_ms=applied_at_ms+1")
        with self.assertRaises(sqlite3.IntegrityError):
            db.execute("DELETE FROM b072_one_shot_migration_receipt")
        authorize(db)
        with self.assertRaises(sqlite3.IntegrityError):
            db.execute("UPDATE b072_one_shot_authorization SET serving_sha=?", ("f" * 40,))
        with self.assertRaises(sqlite3.IntegrityError):
            db.execute("DELETE FROM b072_one_shot_authorization")
        with self.assertRaises(sqlite3.IntegrityError):
            db.execute("INSERT INTO b072_one_shot_authorization VALUES(2,1652,?,?,?,?,?,?,?,?)",
                       (SHA, "x" * 48, RECEIVER, "other", 43, 1_000_000, 2_500_000, 4_000_000))

    def test_claim_requires_activation_and_is_one_shot(self) -> None:
        db = database()
        authorize(db)
        claim = "INSERT OR IGNORE INTO b072_one_shot_claim VALUES(1,1652,?,?,?, ?,?)"
        args = ("SP-0000002500000", 2_500_000, SHA, NONCE, 2_500_001)
        with self.assertRaises(sqlite3.IntegrityError):
            db.execute(claim, args)
        activate(db)
        self.assertEqual(db.execute(claim, args).rowcount, 1)
        self.assertEqual(db.execute(claim, args).rowcount, 0)
        with self.assertRaises(sqlite3.IntegrityError):
            db.execute("UPDATE b072_one_shot_claim SET claimed_at_ms=claimed_at_ms+1")
        with self.assertRaises(sqlite3.IntegrityError):
            db.execute("DELETE FROM b072_one_shot_claim")

    def test_concurrent_claims_linearize_to_exactly_one_insert(self) -> None:
        with tempfile.TemporaryDirectory(prefix="issue-1652-b072-") as temporary:
            path = Path(temporary) / "staging.sqlite"
            seed = database()
            authorize(seed)
            activate(seed)
            serialized = "\n".join(seed.iterdump())
            seed.close()
            setup = sqlite3.connect(path)
            setup.executescript(serialized)
            setup.commit()
            setup.close()
            barrier = Barrier(2)
            statement = "INSERT OR IGNORE INTO b072_one_shot_claim VALUES(1,1652,?,?,?,?,?)"
            params = ("SP-0000002500000", 2_500_000, SHA, NONCE, 2_500_001)

            def claim() -> int:
                connection = sqlite3.connect(path, timeout=5)
                connection.execute("PRAGMA busy_timeout = 5000")
                barrier.wait()
                result = connection.execute(statement, params)
                connection.commit()
                count = result.rowcount
                connection.close()
                return count

            with ThreadPoolExecutor(max_workers=2) as pool:
                inserted = list(pool.map(lambda _: claim(), range(2)))
            check = sqlite3.connect(path)
            total = check.execute("SELECT COUNT(*) FROM b072_one_shot_claim").fetchone()[0]
            check.close()
            self.assertEqual(sum(inserted), 1)
            self.assertEqual(total, 1)

    def test_revocation_blocks_post_activation_claim_and_is_immutable(self) -> None:
        db = database()
        authorize(db)
        activate(db)
        db.execute("INSERT INTO b072_one_shot_revocation VALUES(1,?,?,?)",
                   (NONCE, 2_100_000, "partial_arm_recovery"))
        with self.assertRaises(sqlite3.IntegrityError):
            db.execute("INSERT OR IGNORE INTO b072_one_shot_claim VALUES(1,1652,?,?,?,?,?)",
                       ("SP-0000002500000", 2_500_000, SHA, NONCE, 2_500_001))
        with self.assertRaises(sqlite3.IntegrityError):
            db.execute("UPDATE b072_one_shot_revocation SET revoked_at_ms=revoked_at_ms+1")

    def test_ingress_counter_only_allows_same_correlated_identity_increment(self) -> None:
        db = database()
        db.execute("INSERT INTO b072_one_shot_ingress VALUES(1,?,?,?,?,1,?)",
                   ("SP-0000002500000", 2_500_000, SHA, RECEIVER, 2_500_010))
        db.execute("UPDATE b072_one_shot_ingress SET ingress_count=2,last_ingress_at_ms=2500020 WHERE singleton_id=1")
        with self.assertRaises(sqlite3.IntegrityError):
            db.execute("UPDATE b072_one_shot_ingress SET drill_id='SP-0000002500001', ingress_count=3 WHERE singleton_id=1")
        with self.assertRaises(sqlite3.IntegrityError):
            db.execute("DELETE FROM b072_one_shot_ingress")


class ApprovalAndMachineReceiptTests(unittest.TestCase):
    def test_setup_need_names_are_visible_but_arbitrary_secret_text_is_suppressed(self) -> None:
        exact = "setup required: provision B072_STAGING_D1_WRITE_TOKEN scoped to the fixed staging D1 database"
        self.assertEqual(safe_error(OperatorError(exact)), exact)
        self.assertEqual(safe_error(OperatorError("provider secret value=do-not-print")),
                         "operation failed; provider details were suppressed")

    def test_fake_clock_uses_authorization_time_and_actual_arm_gate_not_future_delay(self) -> None:
        reviewer = {"reviewer_login": "independent-reviewer", "run_id": 42}
        authorized_at, starts_at, ends_at = auth_values(sha=SHA, receiver_version=RECEIVER,
            reviewer=reviewer, run_id=42, now_ms=1_000_000, nonce=NONCE)
        self.assertEqual(authorized_at, 1_000_000)
        self.assertEqual(starts_at - authorized_at, 30 * 60_000)
        db = database()
        db.execute("INSERT INTO b072_one_shot_authorization VALUES(1,1652,?,?,?,?,?,?,?,?)",
            (SHA, NONCE, RECEIVER, "independent-reviewer", 42, authorized_at, starts_at, ends_at))
        arm_at = 1_001_000
        db.execute("INSERT INTO b072_one_shot_activation VALUES(1,?,?,?,?,?)",
            (NONCE, RECEIVER, "* * * * *", arm_at, arm_at + 500))
        self.assertEqual(db.execute("SELECT armed_at_ms FROM b072_one_shot_activation").fetchone()[0], arm_at)

    def test_approval_requires_independent_user_and_exact_environment(self) -> None:
        approval = {"state": "approved", "user": {"id": 7, "login": "independent"},
                    "comment": "approved", "environments": [{"name": "staging"}]}
        observed = datetime(2026, 9, 29, 12, tzinfo=timezone.utc)
        evidence = approved_environment_review([approval], run_id=17, actor="operator", observed_at=observed)
        self.assertEqual(evidence["run_id"], 17)
        self.assertEqual(evidence["approval_observed_at"], observed.isoformat())
        environment_reviewers = [
            {"type": "User", "reviewer": {"id": 1, "login": "operator"}},
            {"type": "User", "reviewer": {"id": 7, "login": "independent"}},
        ]
        require_configured_independent_approver(environment_reviewers, "operator", evidence)
        with self.assertRaises(OperatorError):
            require_configured_independent_approver(environment_reviewers, "operator",
                {**evidence, "reviewer_id": 1, "reviewer_login": "operator"})
        with self.assertRaises(OperatorError):
            require_configured_independent_approver(environment_reviewers, "operator",
                {**evidence, "reviewer_id": 8, "reviewer_login": "other"})
        for actor, envs in (("independent", [{"name": "staging"}]),
                            ("operator", [{"name": "production"}])):
            with self.assertRaises(OperatorError):
                approved_environment_review([{**approval, "environments": envs}], run_id=17, actor=actor)

    def test_1700_success_requires_exact_run_sha_and_machine_cleanup_receipt(self) -> None:
        old_sha = "f" * 40
        run_id = 7654
        run = {"id": run_id, "head_branch": "main", "head_sha": old_sha, "event": "workflow_dispatch",
               "status": "completed", "conclusion": "success",
               "path": ".github/workflows/issue-1700-container-staging-deploy.yml@refs/heads/main"}
        artifact = {"workflow_run": {"id": run_id}, "expired": False,
                    "name": f"issue-1700-existing-completion-{run_id}", "id": 99}
        receipt = {"contract": "issue-1700-existing-runtime-completion-v1", "outcome": "pass",
                   "verification_sha": old_sha,
                   "runtime": {"contract": "corelink-staging-runtime-deployment-proof-v1",
                       "schedule_restored_empty": True, "tail_deleted": True,
                       "receipt": {"contract": "corelink-staging-d1-binding-runtime-v1", "outcome": "pass",
                           "probe_table_dropped": True, "rollback_absence_verified": True}},
                   "before": {"schedules_empty": True},
                   "after": {"schedules_empty": True, "tails_empty": True}}
        self.assertEqual(verify_1700_receipt(run, artifact, receipt, expected_run_id=run_id,
            expected_sha=SHA, expected_verification_sha=old_sha)["outcome"], "pass")
        with self.assertRaises(OperatorError):
            verify_1700_receipt(run, artifact, receipt, expected_run_id=run_id,
                expected_sha=SHA, expected_verification_sha=SHA)


class ProtectedOperatorFlowTests(unittest.TestCase):
    def setUp(self) -> None:
        self.github = FakeGitHub()
        self.cf = FakeCloudflare()
        self.env = execution_env()
        self.events = self.cf.events
        self.now_values = iter((1_800_000_000_000, 1_800_000_000_000, 1_800_000_001_000,
                                1_800_000_001_500, DRILL_AT + 1_000, DRILL_AT + 2_000,
                                DRILL_AT + 3_000, DRILL_AT + 4_000))
        self.now = lambda: next(self.now_values, DRILL_AT + 5_000)
        self.patches = [
            patch.dict("os.environ", self.env, clear=True),
            patch.object(operator.subprocess, "check_output", return_value=SHA),
            patch.object(operator, "Cloudflare", return_value=self.cf),
            patch.object(operator, "worker_preflight", side_effect=self.preflight),
            patch.object(operator, "apply_and_verify_migration", side_effect=self.migrate),
            patch.object(operator, "upload_receiver_version", side_effect=self.upload),
            patch.object(operator, "activate_receiver_version", side_effect=self.activate_receiver),
            patch.object(operator, "readback_postflight", return_value={"verified": True}),
            patch.object(operator.time, "sleep", return_value=None),
        ]

    def preflight(self, cf, route_cf, sha, root_version, receiver_version):
        self.events.append("preflight")
        if sha != SHA or root_version != ROOT_VERSION or receiver_version != RECEIVER_VERSION:
            raise OperatorError("wrong active version preimage")
        return {"root_version": ROOT_VERSION, "receiver_disabled_version": RECEIVER_VERSION,
                "root_schedules": []}

    def migrate(self, cf, token, source_root, now_ms):
        self.events.append("migration-applied-and-read-back")
        return "a" * 64

    def upload(self, source_root, cf, env, sha):
        self.events.append("receiver-version-uploaded-inactive")
        return CANDIDATE_VERSION

    def activate_receiver(self, cf, version, sha, api_path):
        self.events.append("receiver-activated")
        self.cf.active_receiver = version

    def enter(self):
        for item in self.patches:
            item.start()
        self.addCleanup(lambda: [item.stop() for item in reversed(self.patches)])

    def invoke_execute(self, *, cf=None, preflight=None, evidence=None, postflight=None):
        self.enter()
        if cf is not None:
            self.cf = cf
            self.events = cf.events
            self.patches[2].stop()
            self.patches[2] = patch.object(operator, "Cloudflare", return_value=cf)
            self.patches[2].start()
        if preflight is not None:
            self.patches[3].stop()
            self.patches[3] = patch.object(operator, "worker_preflight", side_effect=preflight)
            self.patches[3].start()
        if evidence is not None:
            self.patches.append(patch.object(operator, "terminal_evidence", side_effect=evidence))
            self.patches[-1].start()
        if postflight is not None:
            self.patches[7].stop()
            self.patches[7] = patch.object(operator, "readback_postflight", return_value=postflight)
            self.patches[7].start()
        return execute(ROOT, self.env, self.github, self.cf, root_version=ROOT_VERSION,
            receiver_version=RECEIVER_VERSION, terminal_run_id=1700,
            report_path=Path(tempfile.gettempdir()) / f"issue-1652-b072-{id(self)}.json", now_ms=self.now)

    def test_execute_orders_auth_before_arm_and_requires_correlated_terminal_evidence(self) -> None:
        result = self.invoke_execute()
        self.assertTrue(result["cleanup_complete"])
        self.assertEqual(self.events.index("authorization-write") < self.events.index("receiver-activated"), True)
        self.assertEqual(self.events.index("receiver-activated") < self.events.index("schedule-arm"), True)
        self.assertEqual(self.events.index("schedule-arm") < self.events.index("activation-write"), True)
        self.assertEqual(result["terminal_evidence"]["ingress_count"], 1)
        self.assertEqual(result["terminal_evidence"]["drill_id"], f"SP-{DRILL_AT}")
        self.assertEqual(result["terminal_evidence"]["receipt"]["serving_sha"], SHA)
        self.assertEqual(result["schedule_disarm"]["readback"], [])
        self.assertIn(f"deploy:{RECEIVER_VERSION}", self.events)

    def test_execute_rejects_wrong_identity_before_cloudflare_or_migration(self) -> None:
        self.enter()
        self.github.sha = "f" * 40
        with self.assertRaises(OperatorError):
            execute(ROOT, self.env, self.github, self.cf, root_version=ROOT_VERSION,
                receiver_version=RECEIVER_VERSION, terminal_run_id=1700,
                report_path=Path(tempfile.gettempdir()) / f"issue-1652-b072-bad-id-{id(self)}.json",
                now_ms=self.now)
        self.assertNotIn("migration-applied-and-read-back", self.events)
        self.assertNotIn("schedule-arm", self.events)

    def test_execute_rejects_wrong_preimage_before_migration_or_arm(self) -> None:
        with self.assertRaises(OperatorError):
            self.invoke_execute(preflight=lambda *args: (_ for _ in ()).throw(OperatorError("wrong preimage")))
        self.assertNotIn("migration-applied-and-read-back", self.events)
        self.assertNotIn("schedule-arm", self.events)

    def test_real_preflight_rejects_stale_active_version_before_any_mutation(self) -> None:
        with self.assertRaisesRegex(OperatorError, "explicitly reviewed preimage"):
            operator.worker_preflight(self.cf, self.cf, SHA, "stale-root-version", RECEIVER_VERSION)
        self.assertIn(f"read-active:{ROOT_VERSION}", self.events)
        self.assertIn(f"read-active:{RECEIVER_VERSION}", self.events)
        self.assertFalse(any(event.startswith(("schedule-", "deploy:")) for event in self.events))

    def test_authorization_readback_failure_never_arms_or_issues_delivery(self) -> None:
        failing_cf = FakeCloudflare(fail_authorization_readback=True)
        with self.assertRaises(OperatorError):
            self.invoke_execute(cf=failing_cf)
        self.assertIn("authorization-write", self.events)
        self.assertIn("revocation-write", self.events)
        self.assertNotIn("schedule-arm", self.events)
        self.assertNotIn("activation-write", self.events)
        self.assertEqual(failing_cf.schedules, [])

    def test_partial_activation_failure_revokes_disarms_and_restores_exact_receiver(self) -> None:
        failing_cf = FakeCloudflare(fail_activation=True)
        with self.assertRaises(OperatorError):
            self.invoke_execute(cf=failing_cf)
        self.assertIn("authorization-write", self.events)
        self.assertIn("schedule-arm", self.events)
        self.assertIn("activation-write", self.events)
        self.assertIn("revocation-write", self.events)
        self.assertIn("schedule-disarm", self.events)
        self.assertEqual(self.cf.active_receiver, RECEIVER_VERSION)

    def test_revocation_and_disarm_failure_leave_explicit_residual_risk(self) -> None:
        failing_cf = FakeCloudflare(fail_revocation=True, fail_disarm=True)
        with patch.object(operator, "terminal_evidence", return_value={"ingress_count": 1}):
            with self.assertRaises(OperatorError):
                self.invoke_execute(cf=failing_cf)
        receipt = Path(tempfile.gettempdir()) / f"issue-1652-b072-{id(self)}.json"
        # execute writes a redacted receipt even when cleanup fails.
        import json
        report = json.loads(receipt.read_text(encoding="utf-8"))
        self.assertIn("at most one provider_deferred service-binding POST", report["residual_risk"])
        self.assertFalse(report["cleanup_complete"])
        self.assertEqual(self.cf.active_receiver, RECEIVER_VERSION)

    def test_terminal_correlation_failure_is_not_reported_as_success(self) -> None:
        self.cf.receipts[0]["serving_sha"] = "f" * 40
        with self.assertRaises(OperatorError):
            self.invoke_execute()
        self.assertIn("authorization-write", self.events)
        self.assertIn("schedule-disarm", self.events)

    def test_execute_fails_when_independent_postflight_readback_is_unverified(self) -> None:
        with self.assertRaises(OperatorError):
            self.invoke_execute(postflight={"verified": False, "error": "schedule/version readback mismatch"})
        report_path = Path(tempfile.gettempdir()) / f"issue-1652-b072-{id(self)}.json"
        import json
        report = json.loads(report_path.read_text(encoding="utf-8"))
        self.assertFalse(report["cleanup_complete"])
        self.assertEqual(report["postflight"],
            {"verified": False, "error": "schedule/version readback mismatch"})

    def test_real_postflight_rejects_route_drift_without_serializing_raw_routes(self) -> None:
        nonce = "z" * 48
        self.cf.authorization = {"approval_nonce": nonce, "ends_at_ms": 9_000_000,
            "receiver_worker_revision": CANDIDATE_VERSION, "serving_sha": SHA}
        self.cf.activation = {"approval_nonce": nonce, "receiver_worker_revision": CANDIDATE_VERSION}
        self.cf.revocation = {"approval_nonce": nonce, "revoked_at_ms": 2_000_000,
                              "reason": "disarmed"}
        self.cf.claim_rows = [{"drill_id": f"SP-{DRILL_AT}", "scheduled_at_ms": DRILL_AT,
            "serving_sha": SHA, "approval_nonce": nonce}]
        self.cf.routes = [{"script": operator.ROOT_WORKER, "pattern": "sensitive-route.example"}]
        output = operator.readback_postflight(self.cf, self.cf, "fake-d1-token", ROOT_VERSION,
            RECEIVER_VERSION, CANDIDATE_VERSION, SHA, nonce, 2_100_000)
        self.assertFalse(output["verified"])
        self.assertFalse(output["root_routes_empty"])
        self.assertEqual(output["root_route_count"], 1)
        self.assertNotIn("sensitive-route.example", str(output))
        self.assertNotIn(nonce, str(output))
        self.assertNotIn("approval_nonce", str(output))

    def test_recover_disarms_and_rolls_back_without_rearming_or_replaying(self) -> None:
        self.enter()
        original_nonce = "z" * 48
        self.cf.authorization = {"approval_nonce": original_nonce, "ends_at_ms": 9_000_000,
            "serving_sha": SHA, "approved_run_id": RUN_ID}
        self.cf.activation = {"approval_nonce": original_nonce, "receiver_worker_revision": CANDIDATE_VERSION}
        self.cf.schedules = [operator.ONE_SHOT_CRON]
        original = {"run_id": RUN_ID, "sha": SHA,
            "authorization": {"nonce_sha256": operator.digest(original_nonce.encode())},
            "preimage": {"root_version": ROOT_VERSION, "receiver_disabled_version": RECEIVER_VERSION}}
        with patch.object(operator, "Cloudflare", return_value=self.cf), \
             patch.object(operator, "revoke", wraps=operator.revoke) as revoke_spy:
            result = recover(self.cf, "fake-d1-token", original_report=original, route_cf=self.cf,
                report_path=Path(tempfile.gettempdir()) / f"issue-1652-b072-recover-{id(self)}.json",
                now_ms=lambda: 2_000_000)
        self.assertTrue(result["cleanup_complete"])
        self.assertEqual(result["root_schedules"], [])
        self.assertEqual(result["receiver_version"], RECEIVER_VERSION)
        self.assertEqual(revoke_spy.call_count, 1)
        self.assertNotIn("schedule-arm", self.events)
        self.assertNotIn("receiver-version-uploaded-inactive", self.events)
        self.assertNotIn("delivery-post", self.events)

    def test_recovery_correlation_mismatch_fails_closed_and_retains_residual(self) -> None:
        original_nonce = "z" * 48
        self.cf.authorization = {"approval_nonce": "x" * 48, "ends_at_ms": 1_000_000,
            "serving_sha": SHA, "approved_run_id": RUN_ID}
        self.cf.schedules = [operator.ONE_SHOT_CRON]
        original = {"run_id": RUN_ID, "sha": SHA,
            "authorization": {"nonce_sha256": operator.digest(original_nonce.encode())},
            "preimage": {"root_version": ROOT_VERSION, "receiver_disabled_version": RECEIVER_VERSION}}
        result = recover(self.cf, "fake-d1-token", original_report=original, route_cf=self.cf,
            report_path=Path(tempfile.gettempdir()) / f"issue-1652-b072-recover-mismatch-{id(self)}.json",
            now_ms=lambda: 2_000_000)
        self.assertFalse(result["cleanup_complete"])
        self.assertIn("at most one provider_deferred service-binding POST", result["residual_risk"])
        self.assertNotIn("schedule-arm", self.events)


if __name__ == "__main__":
    unittest.main()
