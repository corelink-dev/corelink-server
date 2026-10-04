#!/usr/bin/env python3
"""Focused tests for the B-373 candidate/post-merge source boundary."""

from __future__ import annotations

import importlib.util
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "verify_b373", ROOT / "scripts/verify_b373_dependabot.py"
)
VERIFY = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(VERIFY)
VERIFY_SNAPSHOT = VERIFY.verify_snapshot
VERIFY_LOCKFILE = VERIFY.verify_lockfile


class B373SourceBoundaryTests(unittest.TestCase):
    def setUp(self):
        # Source-boundary unit tests use the configured server offline. The
        # resolver itself is covered by the identity suite's readback tests.
        from scripts.server_repository import current_repository, resolve_server_repository
        repository = current_repository().full_name
        for mock in (
            patch.object(VERIFY, "REPO", repository),
            patch.object(VERIFY, "verify_snapshot"),
            patch.object(VERIFY, "verify_lockfile"),
            patch.object(VERIFY, "resolve_server_repository", side_effect=lambda explicit: resolve_server_repository(explicit or repository)),
        ):
            mock.start()
            self.addCleanup(mock.stop)

    def test_snapshot_and_lockfile_prerequisites_still_reject_missing_or_drifted_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaisesRegex(VERIFY.CensusError, "snapshot unavailable"):
                VERIFY_SNAPSHOT(root)
            with self.assertRaisesRegex(VERIFY.CensusError, "manifest or lockfile unavailable"):
                VERIFY_LOCKFILE(root)
        # The retained census stays bound to its observed dependency tree.
        with patch.object(VERIFY, "dependency_tree_digest", return_value="0" * 64):
            with self.assertRaisesRegex(VERIFY.CensusError, "not bound"):
                VERIFY_SNAPSHOT(ROOT)

    def test_post_merge_rejects_stdin_and_arbitrary_fixture_before_read(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json") as fixture:
            fixture.write("[]\n")
            fixture.flush()
            for path in (Path("/dev/stdin"), Path(fixture.name)):
                with self.subTest(path=path), patch.object(VERIFY, "read_alerts") as read:
                    result = VERIFY.main(
                        [
                            "--post-merge",
                            "--merged-sha",
                            "704218c5050e99218fa250fc1ff087a2aebd9994",
                            "--alerts-file",
                            str(path),
                        ]
                    )
                    self.assertEqual(result, 2)
                    read.assert_not_called()

    def test_done_fixture_also_requires_authenticated_live_zero(self):
        arguments = ["--alerts-file", str(ROOT / VERIFY.SNAPSHOT)]
        with patch.object(VERIFY, "backlog_b373_done", return_value=True), patch.object(
            VERIFY, "verify_delivered_main_for_candidate"
        ) as delivered, patch.object(
            VERIFY, "read_alerts", return_value=[]
        ) as live:
            self.assertEqual(VERIFY.main(arguments), 0)
            delivered.assert_called_once_with(ROOT)
            live.assert_called_once_with(VERIFY.REPO, None)

    def test_open_state_preserves_historical_candidate_contract(self):
        arguments = ["--alerts-file", str(ROOT / VERIFY.SNAPSHOT)]
        with patch.object(VERIFY, "backlog_b373_done", return_value=False), patch.object(
            VERIFY, "verify_delivered_main_for_candidate"
        ) as delivered, patch.object(VERIFY, "read_alerts") as live:
            self.assertEqual(VERIFY.main(arguments), 0)
            delivered.assert_not_called()
            live.assert_not_called()

    def test_explicit_post_merge_still_rejects_descendant_candidate_tree(self):
        with patch.object(VERIFY, "read_alerts", return_value=[]):
            self.assertEqual(VERIFY.main([
                "--post-merge", "--merged-sha", VERIFY.DELIVERED_MERGE_SHA,
            ]), 2)

    def test_done_candidate_accepts_only_exact_delivered_main_and_ancestry(self):
        main_sha = "1" * 40
        ok = subprocess.CompletedProcess([], 0, "", "")
        with patch.object(VERIFY.subprocess, "run", return_value=ok) as run, patch.object(
            VERIFY, "git", return_value="false"
        ), patch.object(VERIFY, "live_main_sha", side_effect=[main_sha, main_sha]) as live, patch.object(
            VERIFY, "api_json", return_value={"status": "ahead"}
        ) as compare:
            VERIFY.verify_delivered_main_for_candidate(ROOT)
            run.assert_called_once()
            self.assertEqual(run.call_args.args[0], ["git", "merge-base", "--is-ancestor",
                                                     VERIFY.DELIVERED_MERGE_SHA, "HEAD"])
            compare.assert_called_once_with(
                f"/repos/{VERIFY.REPO}/compare/{VERIFY.DELIVERED_MERGE_SHA}...{main_sha}"
            )
            self.assertEqual(live.call_count, 2)

    def test_done_candidate_rejects_stale_or_wrong_main_before_live_api(self):
        arguments = ["--alerts-file", str(ROOT / VERIFY.SNAPSHOT)]
        with patch.object(VERIFY, "backlog_b373_done", return_value=True), patch.object(
            VERIFY, "live_main_sha", side_effect=VERIFY.CensusError("API unavailable")
        ), patch.object(
            VERIFY, "read_alerts"
        ) as live:
            self.assertEqual(VERIFY.main(arguments), 2)
            live.assert_not_called()
        main_sha = "1" * 40
        with patch.object(VERIFY, "backlog_b373_done", return_value=True), patch.object(
            VERIFY, "live_main_sha", side_effect=[main_sha, "0" * 40]
        ), patch.object(VERIFY, "git", return_value="false"), patch.object(
            VERIFY, "api_json", return_value={"status": "ahead"}
        ), patch.object(VERIFY, "read_alerts") as live:
            self.assertEqual(VERIFY.main(arguments), 2)
            live.assert_not_called()

    def test_done_candidate_rejects_non_descendant_before_live_api(self):
        arguments = ["--alerts-file", str(ROOT / VERIFY.SNAPSHOT)]
        main_sha = "1" * 40
        for status in ("behind", "diverged", None):
            with self.subTest(status=status), patch.object(
                VERIFY, "backlog_b373_done", return_value=True
            ), patch.object(VERIFY, "live_main_sha", return_value=main_sha), patch.object(
                VERIFY, "git", return_value="false"
            ), patch.object(VERIFY, "api_json", return_value={"status": status}
            ), patch.object(VERIFY, "read_alerts") as live:
                self.assertEqual(VERIFY.main(arguments), 2)
                live.assert_not_called()

    def test_shallow_trusted_checkout_fails_closed_without_fetch(self):
        def run(*args: str) -> str:
            result = subprocess.run(args, check=True, capture_output=True, text=True)
            return result.stdout.strip()

        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            remote = base / "remote.git"
            source = base / "source"
            shallow = base / "shallow"
            run("git", "init", str(source))
            run("git", "-C", str(source), "config", "user.name", "B373 Test")
            run("git", "-C", str(source), "config", "user.email", "b373@example.test")
            for message in ("root", "delivered", "later"):
                run("git", "-C", str(source), "-c", "commit.gpgsign=false",
                    "commit", "-s", "--allow-empty", "-m", message)
                if message == "delivered":
                    delivered = run("git", "-C", str(source), "rev-parse", "HEAD")
            run("git", "-C", str(source), "branch", "-M", "main")
            run("git", "clone", "--bare", str(source), str(remote))
            run("git", "--git-dir", str(remote), "symbolic-ref", "HEAD", "refs/heads/main")
            run("git", "clone", "--depth=1", remote.as_uri(), str(shallow))
            self.assertEqual(run("git", "-C", str(shallow), "rev-parse",
                                 "--is-shallow-repository"), "true")
            with patch.object(VERIFY, "DELIVERED_MERGE_SHA", delivered), patch.object(
                VERIFY, "live_main_sha", return_value=run("git", "-C", str(source), "rev-parse", "HEAD")
            ), patch.object(VERIFY, "api_json") as compare:
                with self.assertRaisesRegex(VERIFY.CensusError, "full-history"):
                    VERIFY.verify_delivered_main_for_candidate(shallow)
                compare.assert_not_called()

    def test_live_main_ref_and_compare_api_fail_closed(self):
        with patch.object(VERIFY.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, "[]", "")):
            with self.assertRaisesRegex(VERIFY.CensusError, "non-object"):
                VERIFY.live_main_sha()
        with patch.object(VERIFY, "api_json", return_value={"object": {"sha": "bad"}}):
            with self.assertRaisesRegex(VERIFY.CensusError, "valid commit SHA"):
                VERIFY.live_main_sha()

    def test_done_fixture_rejects_live_open_alerts(self):
        arguments = ["--alerts-file", str(ROOT / VERIFY.SNAPSHOT)]
        open_alert = {
            "state": "open", "number": 39,
            "dependency": {"package": {"name": "vitest"}},
            "security_advisory": {
                "ghsa_id": "GHSA-82fw-gwwq-j7x9", "severity": "medium",
                "vulnerabilities": [{}],
            },
        }
        with patch.object(VERIFY, "backlog_b373_done", return_value=True), patch.object(
            VERIFY, "verify_delivered_main_for_candidate"
        ), patch.object(
            VERIFY, "read_alerts", return_value=[open_alert]
        ):
            self.assertEqual(VERIFY.main(arguments), 2)

    def test_done_fixture_rejects_unavailable_live_api(self):
        arguments = ["--alerts-file", str(ROOT / VERIFY.SNAPSHOT)]
        with patch.object(VERIFY, "backlog_b373_done", return_value=True), patch.object(
            VERIFY, "verify_delivered_main_for_candidate"
        ), patch.object(
            VERIFY, "read_alerts", side_effect=VERIFY.CensusError("authenticated API unavailable")
        ):
            self.assertEqual(VERIFY.main(arguments), 2)


if __name__ == "__main__":
    unittest.main()
