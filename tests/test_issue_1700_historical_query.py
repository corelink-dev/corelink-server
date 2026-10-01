import copy
import os
from pathlib import Path
import unittest
from unittest.mock import patch

from scripts import issue_1700_historical_query as query


def aggregate(count, *, metadata='cf-worker-event', event_type='scheduled', outcome='ok', sample=1):
    return {
        'count': count,
        'sampleInterval': sample,
        'value': count,
        'groups': [
            {'key': '$metadata.type', 'value': metadata},
            {'key': '$workers.eventType', 'value': event_type},
            {'key': '$workers.outcome', 'value': outcome},
        ],
    }


def response(aggregates, *, dry=True, account=None, status='COMPLETED', abr=None):
    statistics = {'bytes_read': 10, 'elapsed': 0.1, 'rows_read': 3}
    if abr is not None:
        statistics['abr_level'] = abr
    return {'success': True, 'result': {
        'run': {'accountId': query.ACCOUNT if account is None else account, 'dry': dry, 'status': status},
        'statistics': statistics,
        'calculations': [{'alias': 'event_count', 'calculation': 'count', 'aggregates': aggregates}],
    }}


class HistoricalQueryTests(unittest.TestCase):
    def test_request_is_exact_for_failed_run_and_aggregate_only(self):
        calls = []

        def call(path, body):
            calls.append((path, copy.deepcopy(body)))
            return 200, response([aggregate(3)])

        result = query.collect(call)
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0], (query.QUERY_PATH, query.QUERY))
        self.assertEqual(query.digest(query.QUERY), query.EXPECTED_QUERY_SHA256)
        self.assertEqual(query.RUN_ID, '36829094848')
        self.assertEqual(query.SOURCE_SHA, '7d18bcfc450db97b1b987923050b92971da530a8')
        self.assertEqual(query.VERSION, '002e974d-4271-4630-9745-96ffbfc83af6')
        self.assertEqual(query.QUERY['timeframe'], {'from': 1790839493000, 'to': 1790840995000})
        self.assertEqual(query.QUERY['dry'], True)
        self.assertEqual(query.QUERY['view'], 'calculations')
        self.assertEqual(query.QUERY['chartType'], 'aggregate')
        self.assertTrue(query.QUERY['ignoreSeries'])
        self.assertEqual(query.QUERY['limit'], 100)
        self.assertNotIn('offset', query.QUERY)
        self.assertEqual(query.QUERY['parameters']['groupBys'], [
            {'type': 'string', 'value': key} for key in query.GROUP_KEYS
        ])
        self.assertEqual(result['classification'], 'scheduled_invocations_observed')
        self.assertEqual(result['scheduled_invocation_count'], 3)
        self.assertFalse(result['new_runtime_proof'])

    def test_no_prefix_filter_preserves_unmarked_scheduled_events_and_logs(self):
        self.assertNotIn('$metadata.message', str(query.QUERY))
        result = query.classify(response([
            aggregate(2, metadata='cf-worker-event', event_type='cron', outcome='exception'),
            aggregate(5, metadata='cf-worker-log', event_type='scheduled', outcome='unknown'),
        ]))
        self.assertEqual(result['scheduled_invocation_count'], 2)
        self.assertEqual(result['log_record_count'], 5)
        self.assertEqual(result['classification'], 'scheduled_invocations_observed')

    def test_logs_without_a_scheduled_invocation_are_distinguished(self):
        result = query.classify(response([
            aggregate(4, metadata='cf-worker-log', event_type='scheduled', outcome='unknown'),
        ]))
        self.assertEqual(result['classification'], 'logs_observed_no_scheduled_group')
        self.assertEqual(result['scheduled_invocation_count'], 0)
        self.assertEqual(result['log_record_count'], 4)

    def test_empty_aggregate_and_exact_sampling_are_nonproof(self):
        result = query.classify(response([]))
        self.assertEqual(result['classification'], 'no_groups_returned')
        self.assertEqual(result['sampling'], 'exact')
        self.assertFalse(result['new_runtime_proof'])

    def test_sample_interval_or_abr_prevents_exact_zero_claim(self):
        interval = query.classify(response([aggregate(2, sample=2)]))
        abr = query.classify(response([aggregate(2)], abr=2))
        missing_abr_defaults_to_one = query.classify(response([aggregate(1)]))
        self.assertEqual(interval['classification'], 'sampling_uncertain')
        self.assertEqual(abr['classification'], 'sampling_uncertain')
        self.assertEqual(missing_abr_defaults_to_one['sampling'], 'exact')
        for value in (float('nan'), float('inf')):
            with self.assertRaisesRegex(ValueError, 'abr_level'):
                query.classify(response([aggregate(1)], abr=value))

    def test_limit_reached_is_incomplete_even_without_server_truncation_flag(self):
        result = query.classify(response([aggregate(1) for _ in range(query.LIMIT)]))
        self.assertEqual(result['classification'], 'aggregate_limit_reached')
        self.assertTrue(result['group_limit_reached'])

    def test_only_fixed_enums_and_counts_escape_parser(self):
        result = query.classify(response([
            aggregate(1, metadata='private metadata type', event_type='private event', outcome='private outcome'),
        ]))
        self.assertEqual(result['counts'], {'other|other|other': 1})
        self.assertNotIn('private', str(result))

    def test_unexpected_group_keys_and_bad_numeric_values_are_invalid(self):
        bad_key = aggregate(1)
        bad_key['groups'][0]['key'] = '$metadata.message'
        with self.assertRaisesRegex(ValueError, 'aggregate_group_key'):
            query.classify(response([bad_key]))
        for field, value in [('count', True), ('count', float('inf')), ('sampleInterval', 0)]:
            bad = aggregate(1)
            bad[field] = value
            with self.assertRaisesRegex(ValueError, 'aggregate_count'):
                query.classify(response([bad]))

    def test_wrong_account_dry_and_nonterminal_run_never_report_counts(self):
        wrong_account = query.classify(response([aggregate(8)], account='other'))
        not_dry = query.classify(response([aggregate(8)], dry=False))
        started = query.classify(response([aggregate(8)], status='STARTED'))
        self.assertEqual(wrong_account['classification'], 'account_mismatch')
        self.assertEqual(not_dry['classification'], 'dry_not_confirmed')
        self.assertEqual(started['classification'], 'query_run_incomplete')
        self.assertEqual(wrong_account['counts'], {})
        self.assertEqual(not_dry['counts'], {})
        self.assertEqual(started['counts'], {})

    def test_query_http_errors_are_fixed_and_single_attempt(self):
        for status, classification in ((400, 'query_bad_request'), (401, 'query_unauthorized'),
                                       (403, 'query_forbidden'), (429, 'query_rate_limited'),
                                       (503, 'query_server_error')):
            calls = []
            def call(path, body):
                calls.append((path, body))
                return status, {'errors': [{'message': 'private arbitrary provider detail'}]}
            result = query.collect(call)
            self.assertEqual(len(calls), 1)
            self.assertEqual(result['classification'], classification)
            self.assertNotIn('private arbitrary provider detail', str(result))
            self.assertFalse(result['new_runtime_proof'])

    def test_invalid_responses_and_collection_failures_are_sanitized(self):
        invalid = query.collect(lambda path, body: (200, {'success': True, 'result': {'run': {}, 'calculations': []}}))
        self.assertEqual(invalid['classification'], 'run_status')
        failed = query.collect(lambda path, body: (_ for _ in ()).throw(RuntimeError('secret payload')))
        self.assertEqual(failed['classification'], 'bounded_query_error')
        self.assertNotIn('secret payload', str(failed))

    def test_guard_rejects_mutated_scope_before_call(self):
        calls = []
        with patch.object(query, 'QUERY', {**query.QUERY, 'dry': False}):
            result = query.collect(lambda path, body: calls.append((path, body)))
        self.assertEqual(calls, [])
        self.assertEqual(result['classification'], 'request_hash_mismatch')

    def test_existing_protected_historical_job_and_credential_binding_stay_intact(self):
        workflow = Path('.github/workflows/issue-1700-container-staging-deploy.yml').read_text()
        job = workflow.split('\n  historical_query:\n', 1)[1]
        for required in ("github.repository == 'HuGR-dev/corelink-server'",
                         "github.ref == 'refs/heads/main'", 'github.ref_protected',
                         "inputs.operation == 'historical_query'",
                         "inputs.confirm == 'historical-query-staging-1700'",
                         'environment: staging', 'secrets.CF_API_TOKEN',
                         'EXPECTED_SHA: ${{ inputs.expected_sha }}',
                         'scripts/issue_1700_historical_query.py'):
            self.assertIn(required, job)
        self.assertNotIn('runtime_diagnostic', workflow)
        self.assertNotIn('wrangler', job)

    def test_started_query_and_incomplete_aggregates_return_nonzero(self):
        with patch.dict(os.environ, {
            'EXPECTED_SHA': 'a' * 40, 'GITHUB_SHA': 'a' * 40,
            'GITHUB_RUN_ATTEMPT': '1', 'RUNNER_TEMP': '/tmp',
        }):
            with patch.object(query, 'collect', return_value={
                'query_http': 200, 'account_confirmed': True, 'dry_confirmed': True,
                'query_status': 'STARTED', 'sampling': 'exact',
                'classification': 'query_run_incomplete', 'new_runtime_proof': False,
            }):
                self.assertEqual(query.main(), 1)

    def test_completed_exact_uncapped_query_returns_zero(self):
        with patch.dict(os.environ, {
            'EXPECTED_SHA': 'a' * 40, 'GITHUB_SHA': 'a' * 40,
            'GITHUB_RUN_ATTEMPT': '1', 'RUNNER_TEMP': '/tmp',
        }):
            with patch.object(query, 'collect', return_value={
                'query_http': 200, 'account_confirmed': True, 'dry_confirmed': True,
                'query_status': 'COMPLETED', 'sampling': 'exact',
                'group_limit_reached': False, 'classification': 'no_groups_returned',
                'new_runtime_proof': False,
            }):
                self.assertEqual(query.main(), 0)

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
