import json
import copy
from pathlib import Path
import unittest
from scripts.issue_1700_rollback_quiescence import inspect, HTTP_ORIGIN, HTTP_NONCE, HTTP_START_MS, OLD_RELEASES


RELEASE = 'a' * 40
DIGEST = 'sha256:' + 'b' * 64


def http_fixture():
    started = HTTP_START_MS + 35123
    attempt = {'contract': 'corelink-staging-http-attempt-v1', 'carrier': 'authenticated_http',
               'origin': HTTP_ORIGIN, 'worker_release': RELEASE, 'probe_nonce': HTTP_NONCE,
               'started_at_ms': started, 'scheduled_time_ms': started // 120000 * 120000,
               'deadline_ms': started + 1200000, 'transport_deadline_ms': started + 1260000,
               'request_attempted': True}
    native = {'contract': 'corelink-staging-d1-binding-runtime-v1', 'outcome': 'pass',
              'worker_release': RELEASE, 'probe_nonce': HTTP_NONCE, 'scheduled_time_ms': attempt['scheduled_time_ms'],
              'old_probe_release': '0f785fb9b096afe01247f1057d46377b9f604f13',
              'v5_probe_release': 'cc32b3d819181bf9175e795868f66212aa5456c1', 'v5_prior_execution': 'unknown',
              **dict.fromkeys('old_probe_retired old_probe_tables_absent v5_probe_retired v5_probe_tables_absent v4_probe_catalog_absent parameterized_select failed_batch_observed rollback_absence_verified probe_table_dropped d1_binding_intercepted authorization_absent cf_api_token_absent'.split(), True)}
    def cleanup(version):
        return {'contract': f'corelink-staging-{version}-cleanup-v1', 'old_release': OLD_RELEASES[version],
                'old_nonce': 'issue-1700-recovery-20261001-' + version, 'worker_release': RELEASE,
                'prior_execution': 'unknown', 'prior_admission_present': False, 'container_stopped': True,
                'alarm_absent': True, 'tables_absent': True, 'completed_at_ms': started + 1000}
    status = {'contract': 'corelink-staging-d1-http-proof-v1', 'carrier': 'authenticated_http',
              'worker_release': RELEASE, 'probe_nonce': HTTP_NONCE, 'status': 'complete', 'rollback_safe': True,
              'native_receipt': native, 'v8_cleanup': cleanup('v8'), 'v9_cleanup': cleanup('v9')}
    proof = {'contract': 'corelink-staging-runtime-deployment-proof-v1', 'carrier': 'authenticated_http',
             'account_id': '6a1fc1c626fc2628823e60b9db01f5cd', 'worker_name': 'corelink-staging',
             'workflow_sha': RELEASE, 'worker_release': RELEASE, 'container_image_digest': DIGEST,
             'probe_nonce': HTTP_NONCE, 'origin': HTTP_ORIGIN, 'http_proof': status,
             'receipt': copy.deepcopy(native), 'schedules_empty': True, 'tails_empty': True}
    return {'http_attempt': attempt, 'http_proof': proof, 'expected_release': RELEASE,
            'expected_image_digest': DIGEST, 'http_required': True, 'now_ms': started + 2000}


def empty_read(path):
    return {'success': True, 'result': {'schedules': []} if path == '/schedules' else []}


class QuiescenceTests(unittest.TestCase):
    def test_attempted_http_requires_complete_proof_in_addition_to_empty_inventory(self):
        fixture = http_fixture()
        accepted = inspect(empty_read, **fixture)
        self.assertTrue(accepted['rollback_allowed'])
        self.assertTrue(accepted['http_complete_and_safe'])
        for status in ['not_started', 'running', 'unknown']:
            bad = copy.deepcopy(fixture)
            bad['http_proof']['http_proof'].update(status=status, rollback_safe=False, native_receipt=None)
            result = inspect(empty_read, **bad)
            self.assertFalse(result['rollback_allowed'])
            self.assertEqual(result['reason'], 'http_execution_or_cleanup_unproven')
        for field in ['http_attempt', 'http_proof']:
            bad = copy.deepcopy(fixture)
            bad[field] = None
            self.assertFalse(inspect(empty_read, **bad)['rollback_allowed'])
        self.assertFalse(inspect(empty_read, http_required=True)['rollback_allowed'])

    def test_http_proof_rejects_source_nonce_origin_image_and_native_substitution(self):
        changes = [
            lambda f: f.update(expected_release='c' * 40),
            lambda f: f.update(expected_image_digest='sha256:' + 'c' * 64),
            lambda f: f['http_attempt'].update(origin='https://other.workers.dev'),
            lambda f: f['http_attempt'].update(request_attempted=False),
            lambda f: f['http_attempt'].update(probe_nonce='wrong'),
            lambda f: f['http_attempt'].update(deadline_ms=f['http_attempt']['deadline_ms'] + 1),
            lambda f: f['http_proof'].update(carrier='cron'),
            lambda f: f['http_proof'].update(tails_empty=False),
            lambda f: f['http_proof']['http_proof'].update(rollback_safe=False),
            lambda f: f['http_proof']['http_proof'].update(extra='private'),
            lambda f: f['http_proof']['http_proof'].pop('v8_cleanup'),
            lambda f: f['http_proof']['receipt'].update(outcome='fail'),
            lambda f: f['http_proof']['receipt'].update(cf_api_token_absent=1),
            lambda f: f['http_proof']['http_proof']['native_receipt'].update(scheduled_time_ms=HTTP_START_MS - 1),
            lambda f: f['http_proof']['http_proof']['native_receipt'].update(v5_prior_execution='pass'),
        ]
        for change in changes:
            bad = http_fixture()
            change(bad)
            result = inspect(empty_read, **bad)
            self.assertFalse(result['rollback_allowed'])
            self.assertNotIn('private', json.dumps(result))

    def test_both_cleanup_contracts_require_exact_facts_and_bounded_timestamps(self):
        for version in ['v8', 'v9']:
            for field, value in [('old_release', RELEASE), ('old_nonce', HTTP_NONCE), ('worker_release', 'c' * 40),
                                 ('prior_execution', 'pass'), ('prior_admission_present', 1), ('container_stopped', False),
                                 ('alarm_absent', False), ('tables_absent', False), ('completed_at_ms', HTTP_START_MS),
                                 ('completed_at_ms', http_fixture()['now_ms'] + 1), ('completed_at_ms', True),
                                 ('completed_at_ms', http_fixture()['http_attempt']['deadline_ms']), ('extra', 'private')]:
                bad = http_fixture()
                bad['http_proof']['http_proof'][version + '_cleanup'][field] = value
                self.assertFalse(inspect(empty_read, **bad)['rollback_allowed'], (version, field, value))
            bad = http_fixture()
            del bad['http_proof']['http_proof'][version + '_cleanup']['alarm_absent']
            self.assertFalse(inspect(empty_read, **bad)['rollback_allowed'])

    def test_complete_http_proof_cannot_override_current_provider_activity(self):
        fixture = http_fixture()
        for schedules, tails in [([{'cron': 'private'}], []), ([], [{'id': 'private'}])]:
            def read(path):
                return {'success': True, 'result': {'schedules': schedules} if path == '/schedules' else tails}
            result = inspect(read, **fixture)
            self.assertFalse(result['rollback_allowed'])
            self.assertTrue(result['http_complete_and_safe'])
            self.assertNotIn('private', json.dumps(result))

    def test_exact_empty_readbacks_allow_restore(self):
        calls = []
        def read(path):
            calls.append(path)
            return {'success': True, 'result': {'schedules': []} if path == '/schedules' else []}
        self.assertTrue(inspect(read)['rollback_allowed'])
        self.assertEqual(calls, ['/schedules', '/tails'])

    def test_any_activity_or_malformed_envelope_blocks_restore(self):
        for schedules, tails in [([{'cron': 'do-not-echo'}], []), ([], [{'id': 'do-not-echo'}]),
                                 (None, []), ([], None)]:
            with self.subTest(schedules=schedules, tails=tails):
                def read(path):
                    return {'success': True, 'result': {'schedules': schedules} if path == '/schedules' else tails}
                receipt = inspect(read)
                self.assertFalse(receipt['rollback_allowed'])
                self.assertFalse(receipt['rollback_attempted'])
                self.assertNotIn('do-not-echo', json.dumps(receipt))

    def test_failed_read_is_sanitized_and_never_permits_restore(self):
        def read(_path):
            raise RuntimeError('do-not-echo')
        receipt = inspect(read)
        self.assertFalse(receipt['rollback_allowed'])
        self.assertEqual(receipt['reason'], 'quiescence_unproven')
        self.assertNotIn('do-not-echo', json.dumps(receipt))
        self.assertFalse(inspect(lambda _: {'success': False, 'result': []})['rollback_allowed'])

    def test_guard_precedes_first_runtime_rollback_mutation(self):
        workflow = Path('.github/workflows/issue-1700-container-staging-deploy.yml').read_text()
        rollback = workflow.split('      - name: Restore both preimages after the finite runtime operation', 1)[1]
        self.assertLess(rollback.index('python3 scripts/issue_1700_rollback_quiescence.py'), rollback.index('pnpm exec wrangler deploy ' + chr(92)))
        self.assertEqual(rollback.count('python3 scripts/issue_1700_rollback_quiescence.py'), 2)
        self.assertIn('ROLLBACK_CONTAINER_RESTORE_ATTEMPTED=1 python3 scripts/issue_1700_rollback_quiescence.py\n          pnpm exec wrangler versions deploy', rollback)
        self.assertIn('staging-rollback-quiescence.json', rollback)

    def test_workflow_bootstrap_custody_and_http_carrier_keep_transport_and_secrets_separate(self):
        workflow = Path('.github/workflows/issue-1700-container-staging-deploy.yml').read_text()
        deploy = workflow.split('\n  deploy:\n', 1)[1].split('\n  verify_existing:\n', 1)[0]
        self.assertIn('runs-on: ubuntu-24.04', deploy)
        self.assertLess(deploy.index('actions/setup-node@'), deploy.index('id: preimage'))
        self.assertLess(deploy.index('capture-container-preimage'), deploy.index('id: http_bootstrap'))
        self.assertLess(deploy.index('id: http_bootstrap'), deploy.index('id: deploy'))
        self.assertNotIn('secrets.CORELINK_ADMIN_AUTH_KEY', deploy)
        self.assertIn("input=json.dumps(payload),text=True,check=True", deploy)
        self.assertIn("env={key:os.environ[key] for key in ('PATH','HOME','LANG')", deploy)
        runtime = deploy.split('        id: runtime_probe\n', 1)[1].split('      - name:', 1)[0]
        self.assertIn('issue_1700_http_bootstrap.mjs probe', runtime)
        self.assertNotIn('issue_1700_runtime_probe.mjs', runtime)
        self.assertNotIn('CORELINK_ADMIN_AUTH_KEY', runtime)
        self.assertIn('staging-http-broker/staging-http-probe-attempt.json', deploy)
        rollback = deploy.split('        id: runtime_rollback\n', 1)[1]
        self.assertLess(rollback.index('issue_1700_rollback_quiescence.py'), rollback.index('issue_1700_http_bootstrap.mjs cleanup'))
        self.assertLess(rollback.index('issue_1700_http_bootstrap.mjs cleanup'), rollback.index('pnpm exec wrangler deploy ' + chr(92)))
        self.assertLess(rollback.index('issue_1700_http_bootstrap.mjs close'), rollback.index('pnpm exec wrangler deploy ' + chr(92)))
        condition = rollback.split('        env:', 1)[0]
        self.assertNotIn('failure()', condition)
        self.assertIn("rollout_state='preimage_restore_required'", deploy)
        self.assertIn("rollout_state='preimage_restored'", deploy)
        self.assertIn("runtime_evidence_scope='historical',active_runtime_claim=False", deploy)
        self.assertLess(deploy.index('id: record_runtime'), deploy.index("rollout_state='preimage_restore_required'"))
        self.assertIn('test "$VERIFY_RESTORE_OUTCOME" = success', deploy)
        self.assertEqual(deploy.count("assert config.get('workers_dev') is False"), 3)
