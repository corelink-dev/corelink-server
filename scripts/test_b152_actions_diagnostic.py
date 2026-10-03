#!/usr/bin/env python3
import argparse
import copy
import datetime as dt
import pathlib
import subprocess
import sys
import unittest
from types import SimpleNamespace
from unittest.mock import call, patch

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import b152_actions_diagnostic as diag
import server_repository as RESOLVER  # the module diag.main() imports


def _read_back_fixture_identity():
    # config/github-identity.json may still hold the unread ID 0, which the
    # resolver refuses; keep its owner and names, fill synthetic IDs.
    document = copy.deepcopy(RESOLVER.read_identity_document())
    document["current"]["owner_id"] = 987650000
    for offset, key in enumerate(RESOLVER.REPOSITORY_KEYS, start=1):
        document["current"]["repos"][key]["id"] = 987650000 + offset
    return RESOLVER.parse_identity(document).require_read_back()


FIXTURE_IDENTITY = _read_back_fixture_identity()
FIXTURE_SERVER = FIXTURE_IDENTITY.repository("server").full_name


UTC = dt.timezone.utc


def run(run_id, created, conclusion="failure"):
    return {"id": run_id, "created_at": created, "name": "wf", "conclusion": conclusion}


class B152DiagnosticTests(unittest.TestCase):
    def setUp(self):
        identity = patch.object(RESOLVER, "load_identity", return_value=FIXTURE_IDENTITY)
        identity.start()
        self.addCleanup(identity.stop)

    def test_retired_server_repository_is_refused_before_any_api_call(self):
        for repo in ("HuGR-dev/corelink-server", "HuGR-Labs/corelink-server"):
            with self.subTest(repo=repo), \
                 patch.object(diag.subprocess, "run") as command, \
                 patch("sys.stderr"), \
                 self.assertRaises(SystemExit) as exited:
                diag.main([
                    "--repo", repo,
                    "--start", "2026-08-31T00:00:00Z",
                    "--end", "2026-08-31T01:00:00Z",
                ])
            self.assertEqual(exited.exception.code, 2)
            command.assert_not_called()

    def test_exact_600_second_duration_and_step_checkout_classification(self):
        job = {
            "id": 22,
            "name": "lane",
            "conclusion": "failure",
            "created_at": "2026-08-31T03:57:00Z",
            "started_at": "2026-08-31T04:00:00Z",
            "completed_at": "2026-08-31T04:10:00Z",
            "runner_name": "runner",
            "steps": [
                {"name": "actions/checkout", "status": "completed"},
                {"name": "Install", "status": "in_progress"},
            ],
        }
        item = diag.classify_job(job, run(1, "2026-08-31T04:00:00Z"), 594, 615)
        self.assertEqual(item["duration_seconds"], 600)
        self.assertEqual(item["queue_duration_seconds"], 180)
        self.assertTrue(item["in_window"])
        self.assertEqual(item["step_in_progress"], ["Install"])
        self.assertFalse(item["checkout_incomplete"])
        self.assertEqual(item["steps"][1]["name"], "Install")
        self.assertIsNone(item["steps"][1]["step_id"])

    def test_duration_window_is_inclusive_at_each_boundary(self):
        job = {
            "id": 24,
            "name": "lane",
            "created_at": "2026-08-31T03:59:00Z",
            "started_at": "2026-08-31T04:00:00Z",
            "completed_at": "2026-08-31T04:09:54Z",
            "steps": [],
        }
        self.assertTrue(diag.classify_job(job, run(1, "2026-08-31T04:00:00Z"), 594, 615)["in_window"])
        job["completed_at"] = "2026-08-31T04:10:15Z"
        self.assertTrue(diag.classify_job(job, run(1, "2026-08-31T04:00:00Z"), 594, 615)["in_window"])
        job["completed_at"] = "2026-08-31T04:09:53Z"
        self.assertFalse(diag.classify_job(job, run(1, "2026-08-31T04:00:00Z"), 594, 615)["in_window"])

    def test_fractional_or_negative_durations_fail_closed_before_truncation(self):
        job = {
            "id": 25,
            "name": "lane",
            "created_at": "2026-08-31T03:59:00Z",
            "started_at": "2026-08-31T04:00:00Z",
            "completed_at": "2026-08-31T04:10:00.999Z",
            "steps": [],
        }
        with self.assertRaises(diag.EvidenceUnavailable):
            diag.classify_job(job, run(1, "2026-08-31T04:00:00Z"), 594, 615)
        job["completed_at"] = "2026-08-31T03:59:59.900Z"
        with self.assertRaises(diag.EvidenceUnavailable):
            diag.classify_job(job, run(1, "2026-08-31T04:00:00Z"), 594, 615)
        job["completed_at"] = "2026-08-31T04:10:00Z"
        job["created_at"] = "2026-08-31T03:59:59.500Z"
        with self.assertRaises(diag.EvidenceUnavailable):
            diag.classify_job(job, run(1, "2026-08-31T04:00:00Z"), 594, 615)

    def test_iso_preserves_fractional_cli_window_bounds(self):
        value = diag.parse_time("2026-08-31T04:00:00.123456Z")
        self.assertEqual(diag.iso(value), "2026-08-31T04:00:00.123456Z")

    def test_all_accepted_timestamp_spellings_preserve_six_digits(self):
        variants = (
            "2026-08-31T04:00:00.123456Z",
            "20260831T040000,123456+0000",
            "2026-08-31X04:00:00.123456+00:00",
            "2026-08-31 04:00:00,123456+0000",
        )
        for value in variants:
            with self.subTest(value=value):
                self.assertEqual(diag.iso(diag.parse_time(value)), "2026-08-31T04:00:00.123456Z")

    def test_timestamps_with_more_than_six_fractional_digits_fail_closed(self):
        variants = (
            "2026-08-31T04:00:00.1234567Z",
            "20260831T040000,1234567+0000",
            "2026-08-31X04:00:00.1234567+00:00",
            "2026-08-31 04:00:00,1234567+0000",
        )
        for value in variants:
            with self.subTest(value=value), self.assertRaises(argparse.ArgumentTypeError):
                diag.parse_time(value)
        malformed_run = run(1, "20260831X000000,1234567+0000")
        with patch.object(diag, "run_gh", return_value={"total_count": 1, "workflow_runs": [malformed_run]}):
            with self.assertRaises(diag.EvidenceUnavailable):
                diag.collect_runs(
                    "o/r", dt.datetime(2026, 8, 31, tzinfo=UTC),
                    dt.datetime(2026, 9, 1, tzinfo=UTC),
                )

    def test_incomplete_checkout_is_load_bearing(self):
        job = {
            "id": 23,
            "name": "lane",
            "conclusion": "failure",
            "created_at": "2026-08-31T03:59:00Z",
            "started_at": "2026-08-31T04:00:00Z",
            "completed_at": "2026-08-31T04:10:00Z",
            "steps": [{"name": "Checkout", "status": "in_progress"}],
        }
        item = diag.classify_job(job, run(1, "2026-08-31T04:00:00Z"), 594, 615)
        self.assertTrue(item["checkout_incomplete"])

    def test_pending_step_state_is_retained_as_unfinished_evidence(self):
        job = {
            "id": 29,
            "name": "lane",
            "conclusion": "failure",
            "created_at": "2026-08-31T03:59:00Z",
            "started_at": "2026-08-31T04:00:00Z",
            "completed_at": "2026-08-31T04:10:00Z",
            "steps": [{"name": "Set up Node.js", "status": "pending"}],
        }
        item = diag.classify_job(job, run(1, "2026-08-31T04:00:00Z"), 594, 615)
        self.assertEqual(item["step_in_progress"], [])
        self.assertEqual(item["step_not_completed"], ["Set up Node.js"])
        self.assertEqual(item["metadata_signal"], "runner_death_candidate")

    def test_unknown_step_status_fails_closed_for_checkout_and_non_checkout_steps(self):
        job = {
            "id": 26,
            "name": "lane",
            "created_at": "2026-08-31T03:59:00Z",
            "started_at": "2026-08-31T04:00:00Z",
            "completed_at": "2026-08-31T04:10:00Z",
            "steps": [],
        }
        for name in ("Checkout", "Build"):
            job["steps"] = [{"name": name, "status": "unknown_status"}]
            with self.subTest(name=name), self.assertRaises(diag.EvidenceUnavailable):
                diag.classify_job(job, run(1, "2026-08-31T04:00:00Z"), 594, 615)

    def test_non_string_step_statuses_fail_closed_without_typeerror(self):
        job = {
            "id": 27,
            "name": "lane",
            "created_at": "2026-08-31T03:59:00Z",
            "started_at": "2026-08-31T04:00:00Z",
            "completed_at": "2026-08-31T04:10:00Z",
            "steps": [],
        }
        for status in ([], {}, None, False, 0, 1):
            job["steps"] = [{"name": "Build", "status": status}]
            with self.subTest(status=repr(status)), self.assertRaises(diag.EvidenceUnavailable) as error:
                diag.classify_job(job, run(1, "2026-08-31T04:00:00Z"), 594, 615)
            self.assertEqual(str(error.exception), "job has malformed step evidence")

    def test_unknown_step_conclusion_fails_closed(self):
        job = {
            "id": 30,
            "name": "lane",
            "conclusion": "failure",
            "created_at": "2026-08-31T03:59:00Z",
            "started_at": "2026-08-31T04:00:00Z",
            "completed_at": "2026-08-31T04:10:00Z",
            "steps": [{"name": "Build", "status": "completed", "conclusion": "invented"}],
        }
        with self.assertRaises(diag.EvidenceUnavailable):
            diag.classify_job(job, run(1, "2026-08-31T04:00:00Z"), 594, 615)

    def test_non_string_step_statuses_exit_indeterminate_without_traceback(self):
        base_job = {
            "id": 28,
            "name": "lane",
            "conclusion": "failure",
            "created_at": "2026-08-31T03:59:00Z",
            "started_at": "2026-08-31T04:00:00Z",
            "completed_at": "2026-08-31T04:10:00Z",
            "steps": [],
        }
        failed_run = run(1, "2026-08-31T04:00:00Z")
        for status in ([], {}, None, False, 0, 1):
            job = dict(base_job, steps=[{"name": "Build", "status": status}])
            with self.subTest(status=repr(status)), \
                 patch.object(diag, "collect_runs", return_value=[failed_run]), \
                 patch.object(diag, "collect_jobs", return_value=[job]), \
                 patch("sys.stderr") as stderr:
                self.assertEqual(diag.main([
                    "--repo", FIXTURE_SERVER,
                    "--start", "2026-08-31T00:00:00Z",
                    "--end", "2026-08-31T01:00:00Z",
                ]), 2)
            rendered = "".join(call.args[0] for call in stderr.write.call_args_list)
            self.assertEqual(rendered, "INDETERMINATE: job has malformed step evidence\n")

    def test_truncated_page_splits_and_applies_half_open_bounds(self):
        start = dt.datetime(2026, 8, 31, tzinfo=UTC)
        end = start + dt.timedelta(hours=2)
        calls = []

        def fake(repo, endpoint):
            calls.append(endpoint)
            if "page=1" in endpoint and "T00%3A00%3A00Z..2026-08-31T02%3A00%3A00Z" in endpoint:
                return {"total_count": 1001, "workflow_runs": []}
            return {"total_count": 1, "workflow_runs": [run(7, "2026-08-31T01:00:00Z")]}

        with patch.object(diag, "run_gh", side_effect=fake):
            found = diag.collect_runs("o/r", start, end)
        self.assertEqual([item["id"] for item in found], [7])
        self.assertGreaterEqual(len(calls), 3)

    def test_exactly_1000_runs_splits_to_avoid_the_result_cap(self):
        start = dt.datetime(2026, 8, 31, tzinfo=UTC)
        end = start + dt.timedelta(hours=2)
        calls = []

        def fake(repo, endpoint):
            calls.append(endpoint)
            if "T00%3A00%3A00Z..2026-08-31T02%3A00%3A00Z" in endpoint:
                return {"total_count": 1000, "workflow_runs": []}
            return {"total_count": 0, "workflow_runs": []}

        with patch.object(diag, "run_gh", side_effect=fake):
            self.assertEqual(diag.collect_runs("o/r", start, end), [])
        self.assertGreaterEqual(len(calls), 3)

    def test_short_run_page_with_remaining_total_fails_closed(self):
        with patch.object(diag, "run_gh", return_value={"total_count": 2, "workflow_runs": [run(1, "2026-08-31T00:00:00Z")]}):
            with self.assertRaises(diag.EvidenceUnavailable):
                diag.collect_runs(
                    "o/r", dt.datetime(2026, 8, 31, tzinfo=UTC),
                    dt.datetime(2026, 9, 1, tzinfo=UTC),
                )

    def test_short_job_page_with_remaining_total_fails_closed(self):
        with patch.object(diag, "run_gh", return_value={"total_count": 2, "jobs": [{"id": 1}]}):
            with self.assertRaises(diag.EvidenceUnavailable):
                diag.collect_jobs("o/r", {"id": 9})

    def test_duplicate_job_ids_fail_closed(self):
        with patch.object(diag, "run_gh", return_value={"total_count": 2, "jobs": [{"id": 1}, {"id": 1}]}):
            with self.assertRaises(diag.EvidenceUnavailable):
                diag.collect_jobs("o/r", {"id": 9})

    def test_duplicate_job_ids_across_runs_fail_closed(self):
        runs = [run(9, "2026-08-31T00:00:00Z"), run(10, "2026-08-31T00:01:00Z")]
        job = {
            "id": 1,
            "name": "lane",
            "conclusion": "failure",
            "created_at": "2026-08-31T00:00:00Z",
            "started_at": "2026-08-31T00:00:00Z",
            "completed_at": "2026-08-31T00:01:00Z",
            "steps": [],
        }
        with patch.object(diag, "collect_runs", return_value=runs), \
             patch.object(diag, "collect_jobs", return_value=[job]):
            with self.assertRaises(diag.EvidenceUnavailable):
                diag.collect_evidence(
                    "o/r", dt.datetime(2026, 8, 31, tzinfo=UTC),
                    dt.datetime(2026, 9, 1, tzinfo=UTC), 594, 615,
                )

    def test_startup_failure_is_retained_as_runner_outcome(self):
        startup = run(99, "2026-08-31T00:00:00Z", conclusion="startup_failure")
        startup.update(workflow_id=9, path=".github/workflows/other.yml")
        with patch.object(diag, "collect_runs", return_value=[startup]), \
             patch.object(diag, "collect_jobs", return_value=[]):
            report = diag.collect_evidence(
                "o/r", dt.datetime(2026, 8, 31, tzinfo=UTC),
                dt.datetime(2026, 9, 1, tzinfo=UTC), 594, 615,
            )
        self.assertEqual(report["run_conclusion_counts"], {"startup_failure": 1})
        self.assertEqual(report["run_outcomes"][0]["classification"], "runner_startup_failure")
        self.assertEqual(report["failed_run_count"], 0)

    def test_deleted_buildfailed_identity_is_exact_and_active_same_name_stays_generic(self):
        deleted = run(100, "2026-08-31T00:00:00Z", conclusion="startup_failure")
        deleted.update(workflow_id=303501160, path="BuildFailed")
        active = run(101, "2026-08-31T00:01:00Z", conclusion="startup_failure")
        active.update(
            name="Issue 1679 BuildFailed classification",
            workflow_id=364720472,
            path=".github/workflows/issue-1679-classification.yml",
        )
        self.assertEqual(
            diag.classify_run_outcome(deleted, "startup_failure"),
            "buildfailed_workflow_startup_failure",
        )
        self.assertEqual(diag.classify_run_outcome(active, "startup_failure"), "runner_startup_failure")

        with patch.object(diag, "collect_runs", return_value=[deleted, active]), \
             patch.object(diag, "collect_jobs", return_value=[]):
            report = diag.collect_evidence(
                "o/r", dt.datetime(2026, 8, 31, tzinfo=UTC),
                dt.datetime(2026, 9, 1, tzinfo=UTC), 594, 615,
            )
        self.assertEqual(
            report["run_classification_counts"],
            {"buildfailed_workflow_startup_failure": 1, "runner_startup_failure": 1},
        )
        self.assertEqual(report["run_outcomes"][0]["workflow_id"], 303501160)
        self.assertNotIn("workflow_id", report["run_outcomes"][1])

    def test_partial_deleted_buildfailed_identity_fails_closed(self):
        candidates = (
            {"workflow_id": 303501160, "path": "other.yml"},
            {"workflow_id": 9, "path": "BuildFailed"},
            {"workflow_id": "303501160", "path": "BuildFailed"},
            {"workflow_id": 303501160, "path": None},
            {"workflow_id": "bad", "path": "other.yml"},
            {"workflow_id": 9, "path": ""},
            {"workflow_id": 9},
            {"path": "other.yml"},
            {},
        )
        for identity in candidates:
            with self.subTest(identity=identity), self.assertRaises(diag.EvidenceUnavailable):
                diag.classify_run_outcome(
                    {"id": 102, "conclusion": "startup_failure", **identity},
                    "startup_failure",
                )

    def test_malformed_total_count_fails_closed(self):
        with patch.object(diag, "run_gh", return_value={"total_count": "1000", "workflow_runs": []}):
            with self.assertRaises(diag.EvidenceUnavailable):
                diag.collect_runs(
                    "o/r", dt.datetime(2026, 8, 31, tzinfo=UTC),
                    dt.datetime(2026, 9, 1, tzinfo=UTC),
                )

    def test_unknown_run_conclusion_fails_closed_before_failure_filtering(self):
        bad = run(1, "2026-08-31T00:00:00Z", conclusion="new_terminal_state")
        with patch.object(diag, "run_gh", return_value={"total_count": 1, "workflow_runs": [bad]}):
            with self.assertRaises(diag.EvidenceUnavailable):
                diag.collect_runs(
                    "o/r", dt.datetime(2026, 8, 31, tzinfo=UTC),
                    dt.datetime(2026, 9, 1, tzinfo=UTC),
                )

    def test_unknown_job_conclusion_fails_closed_before_job_filtering(self):
        bad = {"id": 1, "conclusion": "new_terminal_state"}
        with patch.object(diag, "run_gh", return_value={"total_count": 1, "jobs": [bad]}):
            with self.assertRaises(diag.EvidenceUnavailable):
                diag.collect_jobs("o/r", {"id": 9})

    def test_malformed_page_item_fails_closed(self):
        with patch.object(diag, "run_gh", return_value={"total_count": 1, "workflow_runs": ["not-a-run"]}):
            with self.assertRaises(diag.EvidenceUnavailable):
                diag.collect_runs(
                    "o/r", dt.datetime(2026, 8, 31, tzinfo=UTC),
                    dt.datetime(2026, 9, 1, tzinfo=UTC),
                )
        with patch.object(diag, "run_gh", return_value={"total_count": 1, "jobs": ["not-a-job"]}):
            with self.assertRaises(diag.EvidenceUnavailable):
                diag.collect_jobs("o/r", {"id": 9})

    def test_exactly_1000_jobs_probes_page_11(self):
        calls = []

        def fake(repo, endpoint):
            calls.append(endpoint)
            page = int(endpoint.split("&page=")[1].split("&")[0])
            return {
                "total_count": 1000,
                "jobs": [{"id": page * 100 + index} for index in range(100)] if page <= 10 else [],
            }

        with patch.object(diag, "run_gh", side_effect=fake):
            jobs = diag.collect_jobs("o/r", {"id": 9})
        self.assertEqual(len(jobs), 1000)
        self.assertEqual(len(calls), 11)
        self.assertIn("page=11", calls[-1])

    def test_unavailable_log_is_structured_indeterminate(self):
        failed = SimpleNamespace(returncode=1, stderr="HTTP 404 BlobNotFound")
        with patch.object(diag.subprocess, "run", return_value=failed), patch.object(diag.time, "sleep") as sleep:
            logs = diag.fetch_logs("o/r", [{"job_id": 42}])
        self.assertEqual(logs[0]["status"], "indeterminate")
        self.assertEqual(logs[0]["causal"], "indeterminate")
        self.assertEqual(logs[0]["job_id"], 42)
        self.assertEqual(logs[0]["error"], "log retrieval failed")
        self.assertEqual(logs[0]["http_status"], 404)
        self.assertEqual(logs[0]["log_signature"], "indeterminate")
        self.assertIsNone(logs[0]["log_sha256"])
        self.assertEqual(sleep.call_args_list, [call(1), call(2)])

    def test_log_classifier_is_conservative_and_distinguishes_cause_signals(self):
        self.assertEqual(diag.classify_log_text("runner lost communication; operation was canceled"), "runner_cancellation")
        self.assertEqual(diag.classify_log_text("No space left on device (os error 28) while cargo writes"), "enospc_or_linker_failure")
        self.assertEqual(diag.classify_log_text("Error: config.webServer command failed"), "playwright_webserver")
        self.assertEqual(diag.classify_log_text("The job exceeded the maximum allowed execution time"), "job_timeout")
        self.assertEqual(diag.classify_log_text("runner startup failed during billing allocation"), "billing_or_startup")
        self.assertEqual(diag.classify_log_text("assertion failed; runner lost communication"), "test_failure")
        self.assertEqual(diag.classify_log_text("no useful retained diagnostic"), "indeterminate")

    def test_run_gh_retries_bounded_timeouts_with_an_explicit_timeout(self):
        timeout = subprocess.TimeoutExpired(["gh", "api", "secret-endpoint"], diag.GH_API_TIMEOUT_SECONDS)
        success = SimpleNamespace(returncode=0, stdout='{"value": 7}')
        with patch.object(diag.subprocess, "run", side_effect=[timeout, timeout, success]) as command, \
             patch.object(diag.time, "sleep") as sleep:
            self.assertEqual(diag.run_gh("o/r", "repos/o/r/actions/runs"), {"value": 7})
        self.assertEqual(command.call_count, diag.GH_MAX_ATTEMPTS)
        self.assertTrue(all(call.kwargs["timeout"] == diag.GH_API_TIMEOUT_SECONDS for call in command.call_args_list))
        self.assertEqual(sleep.call_args_list, [call(1), call(2)])

    def test_run_gh_timeout_is_sanitized_after_bounded_retries(self):
        timeout = subprocess.TimeoutExpired(["gh", "api", "secret-endpoint"], diag.GH_API_TIMEOUT_SECONDS)
        with patch.object(diag.subprocess, "run", side_effect=[timeout, timeout, timeout]) as command, \
             patch.object(diag.time, "sleep") as sleep, \
             self.assertRaises(diag.EvidenceUnavailable) as error:
            diag.run_gh("o/r", "repos/o/r/actions/runs")
        self.assertEqual(str(error.exception), "gh api timed out after retries")
        self.assertNotIn("secret-endpoint", str(error.exception))
        self.assertEqual(command.call_count, diag.GH_MAX_ATTEMPTS)
        self.assertEqual(sleep.call_args_list, [call(1), call(2)])

    def test_cli_timeout_exits_indeterminate_without_exposing_command_data(self):
        timeout = subprocess.TimeoutExpired(["gh", "api", "secret-endpoint"], diag.GH_API_TIMEOUT_SECONDS)
        with patch.object(diag.subprocess, "run", side_effect=[timeout, timeout, timeout]) as command, \
             patch.object(diag.time, "sleep") as sleep, \
             patch("sys.stderr") as stderr:
            self.assertEqual(diag.main([
                "--repo", FIXTURE_SERVER,
                "--start", "2026-08-31T00:00:00Z",
                "--end", "2026-08-31T01:00:00Z",
            ]), 2)
        rendered = "".join(call.args[0] for call in stderr.write.call_args_list)
        self.assertEqual(rendered, "INDETERMINATE: gh api timed out after retries\n")
        self.assertNotIn("secret-endpoint", rendered)
        self.assertEqual(command.call_count, diag.GH_MAX_ATTEMPTS)
        self.assertEqual(sleep.call_args_list, [call(1), call(2)])

    def test_fetch_logs_retries_timeout_and_never_exposes_timeout_payload(self):
        timeout = subprocess.TimeoutExpired(
            ["gh", "api", "secret-log-endpoint"],
            diag.GH_API_TIMEOUT_SECONDS,
            output="secret output",
            stderr="secret stderr",
        )
        success = SimpleNamespace(returncode=0, stdout=b"runner lost communication; operation canceled")
        with patch.object(diag.subprocess, "run", side_effect=[timeout, success]) as command, \
             patch.object(diag.time, "sleep") as sleep:
            logs = diag.fetch_logs("o/r", [{"job_id": 42}])
        self.assertTrue(logs[0]["available"])
        self.assertIsNone(logs[0]["error"])
        self.assertEqual(logs[0]["log_signature"], "runner_cancellation")
        self.assertTrue(logs[0]["log_sha256"].startswith("sha256:"))
        self.assertEqual(command.call_count, 2)
        self.assertTrue(all(call.kwargs["timeout"] == diag.GH_API_TIMEOUT_SECONDS for call in command.call_args_list))
        self.assertEqual(sleep.call_args_list, [call(1)])

    def test_fetch_logs_reports_final_timeout_as_sanitized_indeterminate(self):
        timeout = subprocess.TimeoutExpired(["gh", "api", "secret-log-endpoint"], diag.GH_API_TIMEOUT_SECONDS)
        with patch.object(diag.subprocess, "run", side_effect=[timeout, timeout, timeout]) as command, \
             patch.object(diag.time, "sleep") as sleep:
            logs = diag.fetch_logs("o/r", [{"job_id": 42}])
        self.assertFalse(logs[0]["available"])
        self.assertEqual(logs[0]["status"], "indeterminate")
        self.assertIsNone(logs[0]["http_status"])
        self.assertEqual(logs[0]["error"], "log retrieval timed out")
        self.assertNotIn("secret-log-endpoint", logs[0]["error"])
        self.assertEqual(command.call_count, diag.GH_MAX_ATTEMPTS)
        self.assertEqual(sleep.call_args_list, [call(1), call(2)])

    def test_official_python_ci_collects_the_b152_suite_on_all_required_triggers(self):
        workflow = (pathlib.Path(__file__).resolve().parent.parent / ".github/workflows/python-tests.yml").read_text(encoding="utf-8")
        # This is a load-bearing mutation test: removing either the required
        # suite declaration or its pytest invocation turns this test red.
        self.assertIn("pull_request:", workflow)
        self.assertIn("push:", workflow)
        self.assertIn("branches: [main]", workflow)
        self.assertIn("workflow_dispatch:", workflow)
        self.assertIn("- 'scripts/**'", workflow)
        self.assertIn("scripts/test_b152_actions_diagnostic.py", workflow)
        self.assertIn("scripts/test_b250_deleted_workflow_startup_failure.py", workflow)
        self.assertIn('python3 -m pytest "${FILES[@]}" "${REQUIRED_SUITES[@]}" -q', workflow)

    def test_focused_b250_workflow_uses_exact_head_without_persisting_credentials(self):
        workflow = (pathlib.Path(__file__).resolve().parent.parent / ".github/workflows/issue-1679-classification.yml").read_text(encoding="utf-8")
        self.assertIn("ref: ${{ github.event.pull_request.head.sha }}", workflow)
        self.assertIn("persist-credentials: false", workflow)
        self.assertIn("actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0", workflow)
        self.assertIn("python3 scripts/test_b152_actions_diagnostic.py", workflow)

    def test_b152_monitor_is_bounded_read_only_and_persists_indeterminate_evidence(self):
        workflow = (pathlib.Path(__file__).resolve().parent.parent / ".github/workflows/b152-actions-monitor.yml").read_text(encoding="utf-8")
        self.assertIn("cron: '*/15 * * * *'", workflow)
        self.assertIn("actions: read", workflow)
        self.assertIn("contents: read", workflow)
        self.assertIn("runs-on: ubuntu-latest", workflow)
        self.assertIn("timeout-minutes: 8", workflow)
        self.assertIn("--fetch-logs", workflow)
        self.assertIn('"run_classification_counts": report.get("run_classification_counts", {})', workflow)
        self.assertIn('"zero_window_jobs_is_not_closure": True', workflow)
        self.assertIn("actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a", workflow)
        self.assertIn("retention-days: 30", workflow)
        self.assertIn("Surface collector unavailability", workflow)
        self.assertNotIn("cat .*logs", workflow)

    def test_missing_gh_is_sanitized_indeterminate_not_a_traceback(self):
        with patch.object(diag.subprocess, "run", side_effect=FileNotFoundError("secret path")), patch("sys.stderr") as stderr:
            self.assertEqual(diag.main([
                "--repo", FIXTURE_SERVER,
                "--start", "2026-08-31T00:00:00Z",
                "--end", "2026-08-31T01:00:00Z",
            ]), 2)
        rendered = "".join(call.args[0] for call in stderr.write.call_args_list)
        self.assertIn("INDETERMINATE: gh api could not be started", rendered)
        self.assertNotIn("secret path", rendered)

    def test_missing_gh_while_fetching_logs_is_sanitized_indeterminate(self):
        report = {"run_ids": [], "failed_jobs": [], "window_jobs": [{"job_id": 42}]}
        with patch.object(diag, "collect_evidence", return_value=report), patch.object(diag.subprocess, "run", side_effect=FileNotFoundError("secret path")), patch("sys.stderr") as stderr:
            self.assertEqual(diag.main([
                "--repo", FIXTURE_SERVER,
                "--start", "2026-08-31T00:00:00Z",
                "--end", "2026-08-31T01:00:00Z",
                "--fetch-logs",
            ]), 2)
        rendered = "".join(call.args[0] for call in stderr.write.call_args_list)
        self.assertIn("INDETERMINATE: gh api could not be started while fetching logs", rendered)
        self.assertNotIn("secret path", rendered)

    def test_output_write_error_is_sanitized_indeterminate_not_a_traceback(self):
        report = {"run_ids": [], "failed_jobs": [], "window_jobs": []}
        with patch.object(diag, "collect_evidence", return_value=report), patch.object(pathlib.Path, "write_text", side_effect=OSError("secret path")), patch("sys.stderr") as stderr:
            self.assertEqual(diag.main([
                "--repo", FIXTURE_SERVER,
                "--start", "2026-08-31T00:00:00Z",
                "--end", "2026-08-31T01:00:00Z",
                "--output", "/private/tmp/secret-report.json",
            ]), 2)
        rendered = "".join(call.args[0] for call in stderr.write.call_args_list)
        self.assertIn("INDETERMINATE: report output could not be written", rendered)
        self.assertNotIn("secret path", rendered)

    def test_available_logs_do_not_establish_a_cause(self):
        report = {"run_ids": [7], "failed_jobs": [], "window_jobs": [{"job_id": 42}]}
        available = [{"job_id": 42, "available": True, "status": "available", "causal": False, "error": None}]
        with patch.object(diag, "collect_evidence", return_value=report), patch.object(diag, "fetch_logs", return_value=available), patch("sys.stdout") as stdout:
            self.assertEqual(diag.main([
                "--repo", FIXTURE_SERVER,
                "--start", "2026-08-31T00:00:00Z",
                "--end", "2026-08-31T01:00:00Z",
                "--fetch-logs",
            ]), 0)
        rendered = "".join(call.args[0] for call in stdout.write.call_args_list)
        self.assertIn('\"status\": \"not_established\"', rendered)
        self.assertIn('\"causal\": false', rendered)

    def test_known_run_control_does_not_accept_missing_run(self):
        with patch.object(diag, "collect_evidence", return_value={
            "failed_jobs": [], "window_jobs": []
        }), patch.object(diag, "collect_runs", return_value=[]):
            self.assertEqual(diag.main([
                "--repo", FIXTURE_SERVER,
                "--start", "2026-08-31T00:00:00Z",
                "--end", "2026-08-31T01:00:00Z",
                "--known-run", "7",
            ]), 2)


if __name__ == "__main__":
    unittest.main()
