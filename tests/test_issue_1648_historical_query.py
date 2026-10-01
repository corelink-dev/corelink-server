import json
import io
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

from scripts import issue_1648_historical_query as query


def event(message, *, worker=query.WORKER, event_type="scheduled", timestamp=query.START_MS):
    return {
        "$metadata": {"service": worker, "message": message},
        "$workers": {"scriptName": worker, "eventType": event_type},
        "timestamp": timestamp,
        "source": {"private_payload": "DO_NOT_PERSIST_1648"},
    }


class HistoricalQueryTests(unittest.TestCase):
    def test_query_is_one_fixed_dry_bounded_production_read(self):
        self.assertEqual(query.ACCOUNT, "6a1fc1c626fc2628823e60b9db01f5cd")
        self.assertEqual(query.QUERY["timeframe"], {"from": 1790798400000, "to": 1790799300000})
        self.assertEqual(query.QUERY["limit"], 100)
        self.assertIs(query.QUERY["dry"], True)
        self.assertEqual(query.QUERY["view"], "events")
        self.assertEqual(query.MAX_RESPONSE_BYTES, 2_000_000)
        self.assertEqual(len(query.QUERY["parameters"]["filters"]), 2)
        self.assertIn("corelink-signup-worker", str(query.QUERY))
        self.assertIn("[audit-archive-cron]", str(query.QUERY))

    def test_fixed_counters_only_and_no_payload_hashes(self):
        message = (
            "[audit-archive-cron] ok=true status=200 rows=4 chunks=1 "
            "failed_partitions=0 failure_codes=none quarantined_rows=0 "
            "quarantined_partitions=0 incomplete=false private=DO_NOT_PERSIST_1648"
        )
        receipt = query.collect(lambda: (200, {
            "success": True,
            "result": {"events": {"events": [event(message)]}},
        }))
        self.assertEqual(receipt["classification"], "matching_historical_events_observed")
        counters = receipt["counters"]
        self.assertEqual(counters["eligible_events"], 1)
        self.assertEqual(counters["counter_lines_parsed"], 1)
        self.assertEqual(counters["success_true"], 1)
        self.assertEqual(counters["status_200"], 1)
        self.assertEqual(counters["rows_sum"], 4)
        self.assertEqual(counters["chunks_sum"], 1)
        self.assertNotIn("private", str(receipt))
        self.assertNotIn("DO_NOT_PERSIST_1648", str(receipt))
        self.assertNotIn("sha256", str(receipt))

    def test_transport_is_one_allowlisted_post_without_redirect_or_retry(self):
        class Response(io.BytesIO):
            status = 200

            def __enter__(self):
                return self

            def __exit__(self, *args):
                self.close()

        class Opener:
            def __init__(self):
                self.calls = []

            def open(self, request, timeout):
                self.calls.append((request, timeout))
                return Response(b'{"success":true}')

        opener = Opener()
        with patch.dict(os.environ, {"CF_API_TOKEN": "test-token"}), patch.object(
            query.urllib.request, "build_opener", return_value=opener
        ):
            status, body = query.request()
        self.assertEqual((status, body), (200, {"success": True}))
        self.assertEqual(len(opener.calls), 1)
        request, timeout = opener.calls[0]
        self.assertEqual(timeout, 20)
        self.assertEqual(request.full_url, query.BASE + query.QUERY_PATH)
        self.assertEqual(request.get_method(), "POST")
        self.assertEqual(json.loads(request.data), query.QUERY)
        self.assertEqual(request.get_header("Authorization"), "Bearer test-token")

    def test_worker_schedule_window_and_tag_predicates_fail_closed(self):
        valid = "[audit-archive-cron] skipped=true reason=erase-auth-key-unbound"
        events = [
            event(valid, worker="wrong-worker"),
            event(valid, event_type="fetch"),
            event(valid, timestamp=query.END_MS),
            event("[other-cron] ok=true"),
        ]
        receipt = query.collect(lambda: (200, {"success": True, "result": {"events": {"events": events}}}))
        self.assertEqual(receipt["classification"], "no_matching_historical_events")
        self.assertEqual(receipt["counters"]["eligible_events"], 0)

    def test_forbidden_and_malformed_responses_are_sanitized(self):
        denied = query.collect(lambda: (403, {"success": False, "errors": [{"message": "DO_NOT_PERSIST_1648"}]}))
        self.assertEqual(denied["classification"], "historical_query_forbidden")
        self.assertNotIn("DO_NOT_PERSIST_1648", str(denied))
        malformed = query.collect(lambda: (200, {"success": True, "result": {"events": {"events": [None] * 101}}}))
        self.assertEqual(malformed["classification"], "historical_query_malformed_or_over_limit")

    def test_workflow_has_exact_sha_confirmation_and_readonly_job_separation(self):
        workflow = Path(".github/workflows/audit-keyed-epoch.yml").read_text()
        self.assertIn("inputs.operation == 'historical_query'", workflow)
        self.assertIn("inputs.expected_sha == github.sha", workflow)
        self.assertIn("inputs.confirm == 'historical-query-production-1648'", workflow)
        self.assertIn("inputs.expected_sha != github.sha", workflow)
        self.assertIn("inputs.confirm != 'historical-query-production-1648'", workflow)
        self.assertIn("github.ref != 'refs/heads/main'", workflow)
        self.assertIn("inputs.operation != 'contract'", workflow)
        self.assertIn("environment: production", workflow)
        self.assertIn("CF_API_TOKEN: ${{ secrets.CF_API_TOKEN }}", workflow)
        self.assertIn("ref: ${{ inputs.expected_sha }}", workflow)
        contract = workflow.split("  contract:\n", 1)[1].split("  historical-query-invalid-request:\n", 1)[0]
        self.assertIn("inputs.operation == 'contract'", contract)
        readonly = workflow.split("  historical-query:\n", 1)[1]
        self.assertIn("always()", readonly)
        self.assertNotIn("cargo test", readonly)
        self.assertNotIn("curl", readonly)
        query_step = readonly.split("- name: Verify exact-SHA read-only query contract\n", 1)[1].split(
            "- name: Preserve fixed-counter receipt only\n", 1
        )[0]
        artifact_step = readonly.split("- name: Preserve fixed-counter receipt only\n", 1)[1]
        self.assertIn("CF_API_TOKEN: ${{ secrets.CF_API_TOKEN }}", query_step)
        self.assertNotIn("CF_API_TOKEN", artifact_step)
        self.assertEqual(workflow.count("CF_API_TOKEN: ${{ secrets.CF_API_TOKEN }}"), 1)

    def test_main_writes_private_sanitized_receipt_and_requires_exact_sha(self):
        with tempfile.TemporaryDirectory() as directory:
            env = {"EXPECTED_SHA": "a" * 40, "GITHUB_SHA": "a" * 40, "RUNNER_TEMP": directory}
            fake_receipt = {"classification": "no_matching_historical_events", "query_http": 200,
                            "api_success": True, "counters": {"event_count": 0}}
            with patch.dict(os.environ, env, clear=False), patch.object(query, "collect", return_value=fake_receipt):
                self.assertEqual(query.main(), 0)
            target = Path(directory) / "issue-1648-historical-query.json"
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)
            self.assertEqual(json.loads(target.read_text()), fake_receipt)
        with patch.dict(os.environ, {"EXPECTED_SHA": "bad", "GITHUB_SHA": "a" * 40}, clear=False):
            with self.assertRaises(SystemExit):
                query.main()


if __name__ == "__main__":
    unittest.main()
