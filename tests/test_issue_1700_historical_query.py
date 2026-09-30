import copy
import json
from pathlib import Path
import unittest
from scripts import issue_1700_historical_query as query


def event():
    native = {'contract': 'corelink-staging-d1-binding-runtime-v1', 'outcome': 'pass',
              'probe_nonce': query.NONCE, 'worker_release': query.RELEASE,
              'scheduled_time_ms': query.START + 60000,
              **{k: True for k in query.NATIVE_CHECKS}, 'unknown_payload': 'do-not-echo'}
    return {'$metadata': {'message': '[staging_d1_runtime_probe] receipt=' + json.dumps(native)},
            '$workers': {'scriptName': 'corelink-staging', 'scriptVersion': {'id': query.VERSION},
                         'eventType': 'scheduled'}, 'timestamp': query.START + 60000,
            'source': {'secret': 'do-not-echo'}}


def response(events):
    return {'success': True, 'result': {'events': {'events': events}}}


class HistoricalQueryTests(unittest.TestCase):
    def test_single_query_is_fixed_and_identity_first(self):
        calls = []
        def call(path, body=None):
            calls.append((path, copy.deepcopy(body)))
            if len(calls) == 1:
                return 200, {'success': True, 'result': {'id': query.ACCOUNT}}, 'a' * 64
            return 200, response([event()]), 'b' * 64
        result = query.collect(call)
        self.assertEqual(calls, [(f'/accounts/{query.ACCOUNT}', None), (query.QUERY_PATH, query.QUERY)])
        self.assertEqual(result['classification'], 'historical_native_receipt_recovered')
        self.assertFalse(result['new_runtime_proof'])
        self.assertNotIn('do-not-echo', json.dumps(result))
        self.assertEqual(query.QUERY['dry'], True)
        self.assertEqual(query.QUERY['limit'], 100)
        self.assertEqual(query.QUERY['timeframe'], {'from': 1790727123000, 'to': 1790728458000})

    def test_denied_identity_prevents_query(self):
        calls = []
        def call(path, body=None):
            calls.append(path)
            return 200, {'success': True, 'result': {'id': 'different'}}, 'a' * 64
        self.assertEqual(query.collect(call)['classification'], 'account_verification_denied')
        self.assertEqual(len(calls), 1)

    def test_401_403_are_precise_and_sanitized(self):
        for status, label in [(401, 'unauthorized'), (403, 'forbidden')]:
            def call(path, body=None):
                if body is None:
                    return 200, {'success': True, 'result': {'id': query.ACCOUNT}}, 'a' * 64
                return status, {'success': False, 'errors': [{'code': 10000, 'message': 'do-not-echo'}]}, 'b' * 64
            result = query.collect(call)
            self.assertEqual(result['classification'], 'historical_query_' + label)
            self.assertEqual(result['api_error_codes'], [10000])
            self.assertNotIn('do-not-echo', json.dumps(result))

    def test_wrong_identity_window_nonce_checks_never_pass(self):
        variants = []
        for field, value in [('scriptName', 'other'), ('scriptVersion', {'id': 'wrong'}), ('eventType', 'fetch')]:
            e = event(); e['$workers'][field] = value; variants.append(e)
        e = event(); e['timestamp'] = query.START - 1; variants.append(e)
        for field, value in [('probe_nonce', 'wrong'), ('worker_release', 'wrong'),
                             ('scheduled_time_ms', query.START - 1), ('outcome', 'fail'),
                             *[(key, False) for key in query.NATIVE_CHECKS]]:
            e = event()
            native = json.loads(e['$metadata']['message'].split('receipt=', 1)[1])
            native[field] = value
            e['$metadata']['message'] = '[staging_d1_runtime_probe] receipt=' + json.dumps(native)
            variants.append(e)
        for e in variants:
            with self.subTest(event=e):
                self.assertEqual(query.classify(response([e]))['classification'], 'no_conclusive_historical_evidence')

    def test_absence_failure_and_malformed_are_not_untouched(self):
        self.assertEqual(query.classify(response([]))['classification'], 'no_conclusive_historical_evidence')
        e = event(); e['$metadata']['message'] = '[staging_d1_runtime_probe] failed reason=probe_failed'
        self.assertEqual(query.classify(response([e]))['classification'], 'historical_attempt_failed_or_claimed')
        e['$metadata']['message'] = '[staging_d1_runtime_probe] receipt=malformed'
        self.assertEqual(query.classify(response([e]))['historical_receipts'], [])
        with self.assertRaises(ValueError):
            query.classify(response([event()] * 101))
        with self.assertRaises(ValueError):
            query.request('/accounts/other')
        with self.assertRaises(ValueError):
            query.request(query.QUERY_PATH, {**query.QUERY, 'dry': False})

    def test_workflow_reuses_repo_secret_only_in_protected_job(self):
        workflow = Path('.github/workflows/issue-1700-container-staging-deploy.yml').read_text()
        job = workflow.split('\n  historical_query:\n', 1)[1]
        for required in ['github.ref_protected', "github.ref == 'refs/heads/main'", 'environment: staging',
                         "inputs.operation == 'historical_query'", "inputs.confirm == 'historical-query-staging-1700'",
                         'secrets.CF_API_TOKEN', 'timeout-minutes: 5', 'inputs.expected_sha']:
            self.assertIn(required, job)
        for forbidden in ['wrangler', 'pnpm', 'STAGING_CF_WORKER_API_TOKEN', 'rollback']:
            self.assertNotIn(forbidden, job)
