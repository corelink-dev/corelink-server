import copy
import json
import os
from pathlib import Path
import unittest
from unittest.mock import patch

from scripts import issue_1700_historical_query as query


def event(message=None, *, version=None, event_type='scheduled', timestamp=None):
    native = {
        'contract': 'corelink-staging-d1-binding-runtime-v1', 'outcome': 'pass',
        'probe_nonce': query.NONCE, 'worker_release': query.RELEASE,
        'scheduled_time_ms': query.START + 60_000,
        'parameterized_select': True, 'failed_batch_observed': True,
        'rollback_absence_verified': True, 'probe_table_dropped': True,
        'd1_binding_intercepted': True, 'authorization_absent': True,
        'cf_api_token_absent': True,
        'old_probe_release': query.OLD_RELEASE, 'old_probe_retired': True,
        'old_probe_tables_absent': True, 'v5_probe_release': query.V5_RELEASE,
        'v5_probe_retired': True, 'v5_probe_tables_absent': True,
        'v5_prior_execution': 'unknown', 'v4_probe_catalog_absent': True,
    }
    if message is None:
        message = query.RECEIPT_PREFIX + json.dumps(native)
    return {
        '$metadata': {'service': 'corelink-staging', 'message': message},
        '$workers': {
            'scriptName': 'corelink-staging',
            'scriptVersion': {'id': query.VERSION if version is None else version},
            'eventType': event_type,
        },
        'timestamp': query.START + 60_000 if timestamp is None else timestamp,
        'source': {'private_payload': 'must-not-be-retained'},
    }


def response(events, *, dry=True, account=None, total=None):
    return {'success': True, 'result': {
        'run': {'dry': dry, 'accountId': query.ACCOUNT if account is None else account},
        'events': {'count': len(events) if total is None else total, 'events': events},
    }}


class HistoricalQueryTests(unittest.TestCase):
    def test_one_post_is_fixed_to_candidate_v8_run_and_window(self):
        calls = []

        def call(path, body):
            calls.append((path, copy.deepcopy(body)))
            return 200, response([event()])

        result = query.collect(call)
        self.assertEqual(calls, [(query.QUERY_PATH, query.QUERY)])
        self.assertEqual(query.QUERY['dry'], True)
        self.assertEqual(query.QUERY['limit'], 100)
        self.assertNotIn('offset', query.QUERY)
        self.assertEqual(query.QUERY['timeframe'], {'from': query.START, 'to': query.END})
        self.assertEqual(query.SOURCE_SHA, '14792a9eb416a3b9426f569d7d1f77079805c13f')
        self.assertEqual(query.VERSION, '725b8a68-523e-42fb-a8b9-b7e1a720fdd0')
        self.assertEqual(result['classification'], 'candidate_receipt_observed')
        self.assertEqual(result['candidate_source_sha'], query.SOURCE_SHA)
        self.assertEqual(result['run_id'], '36812790564')
        self.assertTrue(result['dry_confirmed'])
        self.assertTrue(result['account_confirmed'])
        self.assertEqual(result['counts']['valid_20_key_receipt'], 1)
        self.assertEqual(result['receipt_predicate_true_counts']['exact_20_keys'], 1)
        self.assertFalse(result['new_runtime_proof'])
        self.assertNotIn('must-not-be-retained', json.dumps(result))

    def test_fixed_failure_markers_and_wrong_candidate_metadata_are_counts_only(self):
        events = [
            event(query.PREFIX + ' failed reason=probe_failed'),
            event(query.PREFIX + ' rejected reason=staging_guard'),
            event(version='other'),
            event(event_type='fetch'),
            event(timestamp=query.START - 1),
        ]
        result = query.classify(response(events))
        self.assertEqual(result['classification'], 'candidate_probe_failed_marker_observed')
        self.assertEqual(result['counts']['failure_probe_failed'], 1)
        self.assertEqual(result['counts']['rejected_staging_guard'], 1)
        self.assertEqual(result['counts']['valid_20_key_receipt'], 0)
        self.assertNotIn('must-not-be-retained', json.dumps(result))

    def test_wrong_nonce_missing_key_and_malformed_receipts_never_pass(self):
        malformed = event(query.RECEIPT_PREFIX + 'not-json')
        wrong_nonce = event()
        native = json.loads(wrong_nonce['$metadata']['message'][len(query.RECEIPT_PREFIX):])
        native['probe_nonce'] = 'private-untrusted-value'
        wrong_nonce['$metadata']['message'] = query.RECEIPT_PREFIX + json.dumps(native)
        missing_key = event()
        native = json.loads(missing_key['$metadata']['message'][len(query.RECEIPT_PREFIX):])
        native.pop('v5_prior_execution')
        missing_key['$metadata']['message'] = query.RECEIPT_PREFIX + json.dumps(native)
        result = query.classify(response([malformed, wrong_nonce, missing_key]))
        self.assertEqual(result['counts']['malformed_receipt'], 1)
        self.assertEqual(result['counts']['rejected_receipt'], 2)
        self.assertEqual(result['receipt_predicate_true_counts']['exact_20_keys'], 1)
        self.assertEqual(result['receipt_predicate_true_counts']['nonce'], 1)
        self.assertNotIn('private-untrusted-value', json.dumps(result))

    def test_empty_window_and_limit_truncation_remain_incomplete(self):
        empty = query.classify(response([]))
        self.assertEqual(empty['classification'], 'no_matching_events')
        self.assertFalse(empty['candidate_receipt_observed'])
        capped = query.classify(response([event()] * 100, total=101))
        self.assertEqual(capped['classification'], 'incomplete_limit_reached')
        self.assertTrue(capped['limit_saturated'])
        self.assertTrue(capped['limit_truncated'])
        self.assertTrue(capped['candidate_receipt_observed'])
        self.assertFalse(capped['new_runtime_proof'])
        with self.assertRaises(ValueError):
            query.classify(response([event()] * 101, total=101))

    def test_account_or_dry_mismatch_cannot_be_reported_as_complete(self):
        wrong_account = query.classify(response([event()], account='wrong'))
        self.assertEqual(wrong_account['classification'], 'incomplete_account_not_confirmed')
        not_dry = query.classify(response([event()], dry=False))
        self.assertEqual(not_dry['classification'], 'incomplete_dry_not_confirmed')
        self.assertFalse(not_dry['new_runtime_proof'])

    def test_query_errors_are_fixed_and_never_retried(self):
        calls = []

        def call(path, body):
            calls.append((path, body))
            return 403, {'success': False, 'errors': [{'message': 'private provider text'}]}

        result = query.collect(call)
        self.assertEqual(len(calls), 1)
        self.assertEqual(result['classification'], 'query_forbidden')
        self.assertEqual(result['query_http'], 403)
        self.assertNotIn('private provider text', json.dumps(result))
        with self.assertRaises(ValueError):
            query.request('/accounts/other', query.QUERY)
        with self.assertRaises(ValueError):
            query.request(query.QUERY_PATH, {**query.QUERY, 'dry': False})

    def test_existing_protected_historical_job_is_unchanged_and_bound_to_main(self):
        workflow = Path('.github/workflows/issue-1700-container-staging-deploy.yml').read_text()
        job = workflow.split('\n  historical_query:\n', 1)[1]
        for required in ["github.repository == 'HuGR-dev/corelink-server'",
                         "github.ref == 'refs/heads/main'", 'github.ref_protected',
                         "inputs.operation == 'historical_query'",
                         "inputs.confirm == 'historical-query-staging-1700'",
                         'environment: staging', 'secrets.CF_API_TOKEN',
                         'EXPECTED_SHA: ${{ inputs.expected_sha }}',
                         'scripts/issue_1700_historical_query.py']:
            self.assertIn(required, job)
        self.assertNotIn('runtime_diagnostic', workflow)
        self.assertNotIn('wrangler', job)

    def test_attempt_two_fails_before_query(self):
        with patch.dict(os.environ, {
            'EXPECTED_SHA': 'a' * 40, 'GITHUB_SHA': 'a' * 40,
            'GITHUB_RUN_ATTEMPT': '2',
        }):
            with patch.object(query, 'collect') as collect:
                with self.assertRaisesRegex(SystemExit, 'workflow reruns are not permitted'):
                    query.main()
                collect.assert_not_called()


if __name__ == '__main__':
    unittest.main()
