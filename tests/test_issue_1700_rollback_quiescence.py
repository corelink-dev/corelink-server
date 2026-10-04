import json
import copy
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import threading
import unittest
from scripts.issue_1700_rollback_quiescence import (inspect, read_broker_status, HTTP_ORIGIN, HTTP_NONCE,
    HTTP_START_MS, OLD_RELEASES, BROKER_STATUS_CONTRACT)


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


def never_execute_fixture(state='enabled'):
    ids = [f'{digit * 8}-{digit * 4}-4{digit * 3}-8{digit * 3}-{digit * 12}' for digit in '12345678']
    started, now = HTTP_START_MS, HTTP_START_MS + 15 * 60000
    candidate = {'operation_id': '123456', 'candidate_deployment_id': ids[2], 'candidate_version_id': ids[3],
                 'worker_release': RELEASE, 'image_digest': DIGEST}
    broker = {'contract': 'corelink-staging-http-bootstrap-v2', 'operation_id': '123456', 'worker_release': RELEASE,
              'started_at_ms': started, 'expires_at_ms': started + 45 * 60000, 'state': state,
              'secret_name': 'CORELINK_ADMIN_AUTH_KEY', 'secret_carrier': 'candidate_version',
              'secret_file_written': True, 'secret_file_removed': True, 'candidate_key_confirmed': True,
              'subdomain_enable_attempted': True, 'subdomain_enabled': True,
              'subdomain_restore_attempted': False, 'subdomain_restored': False,
              'rollback_safe': False, 'cleanup_basis': None,
              'probe_command_seen': False, 'admission_closed': True,
              'preimage': {'deployment_id': ids[0], 'version_id': ids[1], 'created_at_ms': started - 10000,
                           'subdomain': {'enabled': False, 'previews_enabled': False}},
              'candidate': candidate,
              'preimage_bindings': [{'name': f'BINDING_{index}', 'type': 'plain_text'} for index in range(35)],
              'failure': None, 'probe_quiescent_at_ms': None, 'pid': 1234}
    if state == 'cleaned':
        broker.update(subdomain_enabled=False, subdomain_restore_attempted=True, subdomain_restored=True,
                      rollback_safe=True, cleanup_basis='never_execute')
    observation = {'contract': BROKER_STATUS_CONTRACT, 'requested_at_ms': now - 10, 'observed_at_ms': now, 'broker': broker}
    options = {'http_required': True, 'http_attempt': None, 'http_proof': {'invalid': True},
               'expected_release': RELEASE, 'expected_image_digest': DIGEST, 'operation_id': '123456',
               'candidate_deployment_id': ids[2], 'candidate_version_id': ids[3],
               'preimage_deployment_id': ids[0], 'preimage_version_id': ids[1],
               'now_ms': now, 'broker_status_reader': lambda: observation}
    return options, observation


class QuiescenceTests(unittest.TestCase):
    def test_fresh_producer_roundtrip_over_actual_local_status_cli_allows_fenced_reserve_denial(self):
        options, observation = never_execute_fixture()
        with tempfile.TemporaryDirectory(prefix='i1700-status-') as directory:
            os.chmod(directory, 0o700)
            with socket.socket(socket.AF_UNIX) as server:
                path = str(Path(directory) / 'broker.sock')
                server.bind(path); os.chmod(path, 0o600); server.listen(1); server.settimeout(5)
                requests, errors = [], []
                def respond():
                    try:
                        connection, _ = server.accept()
                        with connection:
                            connection.settimeout(5)
                            data = b''
                            while b'\n' not in data:
                                data += connection.recv(1024)
                            requests.append(json.loads(data))
                            connection.sendall((json.dumps({'ok': True, 'result': observation['broker']}) + '\n').encode())
                    except Exception as error:
                        errors.append(type(error).__name__)
                thread = threading.Thread(target=respond, daemon=True)
                thread.start()
                options['broker_status_reader'] = lambda: read_broker_status(directory, now=lambda: options['now_ms'])
                result = inspect(empty_read, **options)
                thread.join(5)
                self.assertFalse(thread.is_alive())
                self.assertEqual(errors, [])
                self.assertEqual(requests, [{'command': 'status', 'payload': None}])
                self.assertTrue(result['rollback_allowed'])
                self.assertTrue(result['http_never_executed'])
                self.assertFalse(result['http_complete_and_safe'])
                self.assertEqual(result['_broker_observation']['broker'], observation['broker'])

    def test_never_execute_cleanup_readback_remains_sufficient_for_second_rollback_gate(self):
        options, observation = never_execute_fixture('cleaned')
        result = inspect(empty_read, **options)
        self.assertTrue(result['rollback_allowed'])
        self.assertTrue(result['http_never_executed'])
        self.assertEqual(result['_broker_observation']['broker']['cleanup_basis'], 'never_execute')
        observation['broker']['cleanup_basis'] = 'complete_proof'
        self.assertFalse(inspect(empty_read, **options)['rollback_allowed'])

    def test_a_fenced_failed_bind_and_its_reconciled_cleanup_permit_the_exact_restore(self):
        bind_failure = {'phase': 'bind_enable_subdomain', 'endpoint_label': 'subdomain', 'http_status': 502,
                        'cf_error_codes': [], 'cf_message_class': None, 'validation_failed': None,
                        'timed_out': False, 'aborted': False}
        options, observation = never_execute_fixture()
        observation['broker'].update(state='bind_failed', subdomain_enabled=False, candidate_key_confirmed=False,
                                     failure=bind_failure)
        self.assertTrue(inspect(empty_read, **options)['rollback_allowed'])
        observation['broker'].update(state='cleaned', cleanup_basis='never_execute', rollback_safe=True,
                                     candidate_key_confirmed=True, subdomain_restore_attempted=True,
                                     subdomain_restored=True)
        self.assertTrue(inspect(empty_read, **options)['rollback_allowed'])
        # A bind that never reached the toggle needs no restore write.
        observation['broker'].update(subdomain_enable_attempted=False, subdomain_restore_attempted=False)
        self.assertTrue(inspect(empty_read, **options)['rollback_allowed'])
        # Cleanup keeps custody across transport failures, so a cleanup-phase failure is fine
        # once cleaned; and cleanup re-proves ownership, not the key, so an unconfirmed key is fine.
        for allowed in ({'failure': dict(bind_failure, phase='cleanup_restore_subdomain')},
                        {'candidate_key_confirmed': False}):
            options, observation = never_execute_fixture('cleaned')
            observation['broker'].update({'failure': bind_failure, 'subdomain_enable_attempted': True, **allowed})
            self.assertTrue(inspect(empty_read, **options)['rollback_allowed'], allowed)
        refused = [
            lambda b: b.update(failure=dict(bind_failure, phase='probe_verify_candidate')),
            lambda b: b.update(probe_quiescent_at_ms=b['started_at_ms']),  # never_execute has no attempt bound
            lambda b: b.update(failure='bind_enable_subdomain'),
            lambda b: b.update(subdomain_restore_attempted=True, subdomain_enable_attempted=False),  # restore, no enable
            lambda b: b.update(state='bind_failed', cleanup_basis=None, rollback_safe=False,
                               subdomain_restored=False, subdomain_enabled=True),
            lambda b: b.update(state='enabled', cleanup_basis=None, rollback_safe=False, subdomain_restored=False,
                               subdomain_enabled=True, subdomain_enable_attempted=True),  # enabled with a failure
            lambda b: b.update(probe_command_seen=True),
            lambda b: b.update(candidate_key_confirmed=1),
        ]
        for change in refused:
            options, observation = never_execute_fixture('cleaned')
            observation['broker'].update(failure=bind_failure, subdomain_enable_attempted=True)
            change(observation['broker'])
            self.assertFalse(inspect(empty_read, **options)['rollback_allowed'])

    def test_a_failed_attempt_is_quiescent_only_after_its_hard_stop_then_restorable(self):
        # Attempt recorded, the Container exited 1 at boot, no proof: the broker fenced the
        # failed probe, and nothing can still be running once the attempt's hard stop passed.
        attempt = http_fixture()['http_attempt']
        stop = attempt['scheduled_time_ms'] + 120_000 + 1_200_000 + 60_000
        options, observation = never_execute_fixture()
        broker = observation['broker']
        broker.update(state='probe_failed', probe_command_seen=True, probe_quiescent_at_ms=stop,
                      started_at_ms=attempt['started_at_ms'] - 60_000)
        broker['expires_at_ms'] = broker['started_at_ms'] + 45 * 60000
        broker['preimage']['created_at_ms'] = broker['started_at_ms'] - 10_000
        def at(now):
            observation.update(requested_at_ms=now - 10, observed_at_ms=now)
            options['now_ms'] = now
            return inspect(empty_read, **dict(options, http_attempt=attempt, http_proof=None))
        early = at(stop - 1)
        self.assertFalse(early['rollback_allowed']); self.assertFalse(early['http_attempt_quiescent'])
        later = at(stop)
        self.assertTrue(later['rollback_allowed']); self.assertTrue(later['http_attempt_quiescent'])
        self.assertFalse(later['http_never_executed'])
        broker.update(state='cleaned', cleanup_basis='expired_attempt', rollback_safe=True, subdomain_enabled=False,
                      subdomain_restore_attempted=True, subdomain_restored=True)
        self.assertTrue(at(stop + 60_000)['rollback_allowed'])
        refused = [
            lambda b, a: b.update(probe_quiescent_at_ms=None),
            lambda b, a: b.update(probe_command_seen=False),
            lambda b, a: b.update(admission_closed=False),
            lambda b, a: b.update(cleanup_basis='never_execute'),
            lambda b, a: b.update(candidate_key_confirmed=False),
            lambda b, a: b.update(failure={'phase': 'bind_enable_subdomain'}),
            lambda b, a: b.update(probe_quiescent_at_ms=stop + 120_000),  # broker's own bound not reached
            lambda b, a: a.update(scheduled_time_ms=a['scheduled_time_ms'] + 120_000,
                                  started_at_ms=a['started_at_ms'] + 120_000),  # the attempt's bound not reached
            lambda b, a: a.update(probe_nonce='issue-1700-recovery-20261002-v15'),
            lambda b, a: a.update(invalid=True),
        ]
        for change in refused:
            options, observation = never_execute_fixture()
            broker = observation['broker']
            broker.update(state='cleaned', cleanup_basis='expired_attempt', rollback_safe=True, subdomain_enabled=False,
                          subdomain_restore_attempted=True, subdomain_restored=True, probe_command_seen=True,
                          probe_quiescent_at_ms=stop, started_at_ms=attempt['started_at_ms'] - 60_000)
            broker['expires_at_ms'] = broker['started_at_ms'] + 45 * 60000
            broker['preimage']['created_at_ms'] = broker['started_at_ms'] - 10_000
            changed = dict(attempt)
            change(broker, changed)
            observation.update(requested_at_ms=stop + 60_000 - 10, observed_at_ms=stop + 60_000)
            options['now_ms'] = stop + 60_000
            self.assertFalse(inspect(empty_read, **dict(options, http_attempt=changed, http_proof=None))['rollback_allowed'])

    def test_missing_ledger_does_not_replace_positive_live_broker_custody(self):
        options, _ = never_execute_fixture()
        options['broker_status_reader'] = None
        self.assertFalse(inspect(empty_read, **options)['rollback_allowed'])
        for attempt in [{'invalid': True}, http_fixture()['http_attempt']]:
            options, _ = never_execute_fixture()
            options['http_attempt'] = attempt
            options['broker_status_reader'] = lambda: self.fail('an attempt forbids never_execute admission')
            self.assertFalse(inspect(empty_read, **options)['rollback_allowed'])
        options, _ = never_execute_fixture()
        def unavailable():
            raise RuntimeError('private-status-error')
        options['broker_status_reader'] = unavailable
        result = inspect(empty_read, **options)
        self.assertFalse(result['rollback_allowed'])
        self.assertNotIn('private-status-error', json.dumps(result))

    def test_stale_forged_expired_wrong_tuple_or_nonfenced_status_cannot_allow_restore(self):
        changes = [
            lambda o, s: s.update(contract='forged'), lambda o, s: s.update(extra='private'),
            lambda o, s: s.update(requested_at_ms=o['now_ms'] - 5001),
            lambda o, s: s.update(observed_at_ms=o['now_ms'] + 1),
            lambda o, s: o.update(now_ms=o['now_ms'] + 5001),
            lambda o, s: s['broker'].update(operation_id='999'),
            lambda o, s: s['broker'].update(worker_release='c' * 40),
            lambda o, s: s['broker'].update(expires_at_ms=o['now_ms']),
            lambda o, s: s['broker'].update(expires_at_ms=s['broker']['expires_at_ms'] + 1),
            lambda o, s: s['broker'].update(state='unknown'),
            lambda o, s: s['broker'].update(state='prepared'),
            lambda o, s: s['broker'].update(probe_command_seen=True),
            lambda o, s: s['broker'].update(probe_command_seen=0),
            lambda o, s: s['broker'].update(admission_closed=False),
            lambda o, s: s['broker'].update(secret_file_removed=False),
            lambda o, s: s['broker'].update(candidate_key_confirmed=False),
            lambda o, s: s['broker'].update(secret_carrier='script_secret'),
            lambda o, s: s['broker'].update(contract='corelink-staging-http-bootstrap-v1'),
            lambda o, s: s['broker'].update(rollback_safe=True),
            lambda o, s: s['broker']['candidate'].update(candidate_version_id=s['broker']['preimage']['version_id']),
            lambda o, s: s['broker']['candidate'].update(operation_id='999'),
            lambda o, s: s['broker']['candidate'].update(image_digest='sha256:' + 'c' * 64),
            lambda o, s: s['broker']['preimage']['subdomain'].update(enabled=True),
            lambda o, s: s['broker']['preimage_bindings'][0].update(name='CORELINK_ADMIN_AUTH_KEY'),
            lambda o, s: s['broker'].update(extra='private'),
            lambda o, s: s['broker'].pop('admission_closed'),
            # A recorded provider-call failure means the broker is not a clean never-execute owner.
            lambda o, s: s['broker'].update(failure={'phase': 'cleanup_delete_secret', 'endpoint_label': 'secret_named',
                                                      'http_status': 403, 'cf_error_codes': [10000],
                                                      'cf_message_class': 'authentication', 'validation_failed': None,
                                                      'timed_out': False, 'aborted': False}),
            lambda o, s: s['broker'].pop('failure'),
        ]
        for change in changes:
            options, observation = never_execute_fixture()
            change(options, observation)
            result = inspect(empty_read, **options)
            self.assertFalse(result['rollback_allowed'])
            self.assertFalse(result['http_never_executed'])
            self.assertNotIn('private', json.dumps(result))

    def test_broker_status_producer_is_bounded_scrubbed_and_sanitizes_failure(self):
        options, observation = never_execute_fixture()
        def runner(args, **kwargs):
            self.assertEqual(args[-2:], ['status', '/private/fixture'])
            self.assertEqual(kwargs['timeout'], 5)
            self.assertTrue(set(kwargs['env']) <= {'PATH', 'HOME', 'LANG'})
            return subprocess.CompletedProcess(args, 0, json.dumps(observation['broker']), '')
        actual = read_broker_status('/private/fixture', runner=runner, now=lambda: options['now_ms'])
        self.assertEqual(actual['broker'], observation['broker'])
        for bad in [subprocess.CompletedProcess([], 1, 'private', 'private'),
                    subprocess.CompletedProcess([], 0, 'x' * 32769, 'private')]:
            with self.assertRaisesRegex(ValueError, '^broker status unproven$'):
                read_broker_status('/private/fixture', runner=lambda *a, **k: bad)

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
        self.assertIn('worker_restore_permitted=0\n          ROLLBACK_CONTAINER_RESTORE_ATTEMPTED=1 python3 scripts/issue_1700_rollback_quiescence.py\n'
                      '          worker_restore_permitted=1\n          restore_worker_preimage\n', rollback)
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
        start = deploy.split('        id: http_bootstrap\n', 1)[1].split('      - name:', 1)[0]
        # A failed start prints one redacted classification line, then still fails the step.
        failed = start.split('except subprocess.CalledProcessError:', 1)[1]
        self.assertIn("'scripts/issue_1700_http_bootstrap.mjs','failure',broker]", failed)
        self.assertLess(failed.index("'failure',broker"), failed.index('raise SystemExit(1)'))
        self.assertNotIn('CLOUDFLARE_API_TOKEN', failed)
        self.assertNotIn('payload', failed)
        # The admin key rides the candidate upload; nothing writes a script-level secret.
        upload = deploy.split('        id: deploy\n', 1)[1].split('      - name:', 1)[0]
        self.assertIn('--secrets-file "$secrets_file"', upload)
        self.assertIn('secrets_file="$RUNNER_TEMP/staging-http-broker/candidate-secrets.json"', upload)
        self.assertLess(upload.index("trap 'rm -f -- \"$secrets_file\"' EXIT"), upload.index('pnpm exec wrangler deploy'))
        self.assertNotIn('secret put', deploy)
        self.assertNotIn('secret bulk', deploy)
        self.assertNotIn('versions secret', deploy)
        # Each exact-preimage restore is followed by the provider readback that the key is gone.
        for step_id in ('early_rollback', 'runtime_rollback'):
            with self.subTest(step=step_id):
                body = deploy.split(f'        id: {step_id}\n', 1)[1].split('\n      - name:', 1)[0]
                self.assertEqual(body.count("'scripts/issue_1700_http_bootstrap.mjs','verify_restored'"), 1)
                self.assertLess(body.index('wrangler versions deploy "${PREIMAGE_VERSION_ID}@100%"'),
                                body.index("'verify_restored'"))
                self.assertIn('PREIMAGE_DEPLOYMENT_ID: ${{ steps.preimage.outputs.preimage_deployment_id }}', body)
                self.assertIn('staging-http-bootstrap-restore.json', body)
        self.assertIn('${{ runner.temp }}/staging-http-bootstrap-restore.json', deploy)
        self.assertNotIn('candidate-secrets.json', deploy.split('Upload redacted route-free deployment receipt', 1)[1])
        runtime = deploy.split('        id: runtime_probe\n', 1)[1].split('      - name:', 1)[0]
        self.assertIn('issue_1700_http_bootstrap.mjs probe', runtime)
        self.assertNotIn('issue_1700_runtime_probe.mjs', runtime)
        self.assertNotIn('CORELINK_ADMIN_AUTH_KEY', runtime)
        self.assertIn('staging-http-broker/staging-http-probe-attempt.json', deploy)
        rollback = deploy.split('        id: runtime_rollback\n', 1)[1]
        self.assertLess(rollback.index('trap finish_rollback EXIT'), rollback.index('verify_issue_1700_route_inventory.py'))
        self.assertLess(rollback.index('issue_1700_rollback_quiescence.py'), rollback.index('          broker_cleanup\n'))
        self.assertLess(rollback.index('          broker_cleanup\n'), rollback.index('pnpm exec wrangler deploy ' + chr(92)))
        self.assertNotIn('issue_1700_http_bootstrap.mjs close', deploy)
        self.assertIn('PREIMAGE_DEPLOYMENT_ID: ${{ steps.preimage.outputs.preimage_deployment_id }}', rollback)
        condition = rollback.split('        env:', 1)[0]
        self.assertNotIn('failure()', condition)
        self.assertIn("rollout_state='preimage_restore_required'", deploy)
        self.assertIn("rollout_state='preimage_restored'", deploy)
        self.assertIn("runtime_evidence_scope='historical',active_runtime_claim=False", deploy)
        self.assertLess(deploy.index('id: record_runtime'), deploy.index("rollout_state='preimage_restore_required'"))
        self.assertIn('test "$VERIFY_RESTORE_OUTCOME" = success', deploy)
        shutdown = deploy.split('        id: http_broker_shutdown\n', 1)[1].split('      - name:', 1)[0]
        self.assertIn("if: always() && steps.http_bootstrap.outcome != 'skipped'", shutdown)
        self.assertIn('timeout-minutes: 1', shutdown)
        self.assertIn('issue_1700_http_bootstrap.mjs shutdown', shutdown)
        self.assertNotIn("== 'success'", shutdown)
        self.assertNotIn('continue-on-error', shutdown)
        self.assertLess(deploy.index('Clean owned bootstrap when candidate execution was never reached'), deploy.index('id: http_broker_shutdown'))
        self.assertLess(deploy.index('id: http_broker_shutdown'), deploy.index('Require historical native proof'))
        self.assertIn('test "$BROKER_SHUTDOWN_OUTCOME" = success', deploy)
        self.assertIn('staging-http-broker-status.json', deploy)
        self.assertIn('staging-http-broker-shutdown.json', deploy)
        self.assertEqual(deploy.count("assert config.get('workers_dev') is False"), 4)


class RollbackRestoreGuaranteeTests(unittest.TestCase):
    """Run the real rollback step scripts against stub tools. Once ownership, quiescence and the
    broker cleanup are proven, the exact Worker preimage restore must be attempted however the
    Container steps end; a failed or unknown second quiescence gate must withhold it."""

    def run_step(self, step_id, fail_on=None, after_upload=False, fail_times=None, outcome=None):
        import yaml
        workflow = yaml.safe_load(Path('.github/workflows/issue-1700-container-staging-deploy.yml').read_text())
        step = next(item for item in workflow['jobs']['deploy']['steps'] if item.get('id') == step_id)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bin_dir, log, failures = root / 'bin', root / 'calls.log', root / 'failures'
            bin_dir.mkdir()
            for tool in ('pnpm', 'node', 'python3'):
                stub = bin_dir / tool
                stub.write_text(
                    '#!/bin/bash\ncat >/dev/null 2>&1 || true\n'
                    f'uploaded=0; grep -q "wrangler deploy.*rollback" "{log}" 2>/dev/null && uploaded=1\n'
                    f'echo "{tool} $*" >> "{log}"\n'
                    + ('if [ "$1" = -c ]; then echo "${STUB_OUTCOME:-}"; exit 0; fi\n' if tool == 'python3' else '') +
                    'if [ -n "${FAIL_ON:-}" ] && [[ "$*" == *"$FAIL_ON"* ]] && '
                    '{ [ -z "${AFTER_UPLOAD:-}" ] || [ "$uploaded" = 1 ]; }; then\n'
                    f'  count=$(cat "{failures}" 2>/dev/null || echo 0)\n'
                    '  if [ -z "${FAIL_TIMES:-}" ] || [ "$count" -lt "$FAIL_TIMES" ]; then\n'
                    f'    echo $((count + 1)) > "{failures}"; exit 7\n'
                    '  fi\n'
                    'fi\n')
                stub.chmod(0o755)
            env = {key: f'stub-{key.lower()}' for key in step.get('env', {})}
            env.update(PATH=f'{bin_dir}:/usr/bin:/bin', RUNNER_TEMP=str(root), GITHUB_OUTPUT=str(root / 'out'),
                       PREIMAGE_VERSION_ID='preimage-version', PREIMAGE_CONTAINER_IMAGE='registry/x@sha256:' + 'c' * 64,
                       HOME=str(root), CLEANUP_RETRY_SECONDS='0', CLOUDFLARE_API_TOKEN='stub-token')
            for key, value in (('FAIL_ON', fail_on), ('AFTER_UPLOAD', '1' if after_upload else None),
                               ('FAIL_TIMES', None if fail_times is None else str(fail_times)), ('STUB_OUTCOME', outcome)):
                if value is not None:
                    env[key] = value
            result = subprocess.run(['bash', '-c', step['run']], env=env, capture_output=True, text=True,
                                    stdin=subprocess.DEVNULL, timeout=60)
            calls = log.read_text().splitlines() if log.exists() else []
            residual = root / 'staging-rollback-residual.json'
            residual = json.loads(residual.read_text()) if residual.exists() else None
        return result.returncode, calls, residual

    @staticmethod
    def restores(calls):
        return [i for i, line in enumerate(calls) if 'wrangler versions deploy preimage-version@100%' in line]

    @staticmethod
    def uploads(calls, config):
        return [i for i, line in enumerate(calls) if 'wrangler deploy --' in line and config in line]

    def test_container_failures_before_or_after_the_upload_still_restore_the_worker(self):
        cases = []
        for step_id, config in (('runtime_rollback', 'rollback-runtime.toml'), ('early_rollback', 'rollback.toml')):
            # Before the upload: the first Container read and the candidate digest check (GPT #2).
            cases += [(step_id, config, 'read-container-state', False, False),
                      (step_id, config, 'verify-container-digest', False, False)]
            # After the upload: the bounded wait and the restored digest check.
            cases += [(step_id, config, 'wait-container-state', True, True),
                      (step_id, config, 'verify-container-digest', True, True)]
        for step_id, config, fail_on, after_upload, uploaded in cases:
            with self.subTest(step=step_id, fail_on=fail_on, after_upload=after_upload):
                code, calls, residual = self.run_step(step_id, fail_on, after_upload)
                self.assertNotEqual(code, 0)
                restores = self.restores(calls)
                self.assertEqual(len(restores), 1, calls)
                self.assertEqual(bool(self.uploads(calls, config)), uploaded, calls)
                cleanup = max(i for i, line in enumerate(calls) if 'issue_1700_http_bootstrap.mjs cleanup' in line)
                self.assertLess(cleanup, restores[0])
                # The Worker preimage is read back inside the restore.
                self.assertTrue(any(line.startswith('python3 -') for line in calls[restores[0] + 1:]), calls)
                self.assertIsNone(residual)

    def test_a_failed_or_unknown_second_quiescence_gate_never_restores_old_code(self):
        code, calls, residual = self.run_step('runtime_rollback', 'issue_1700_rollback_quiescence.py', after_upload=True)
        self.assertNotEqual(code, 0)
        self.assertEqual(self.restores(calls), [], calls)
        self.assertEqual(len(self.uploads(calls, 'rollback-runtime.toml')), 1)
        self.assertEqual(residual, {'contract': 'issue1700-rollback-residual-v1', 'reason': 'second_quiescence_unproven',
                                    'worker_restore_attempted': False, 'active_runtime_claim': False})

    def test_preliminary_read_and_first_gate_failures_close_owned_origin_and_write_residual(self):
        cases = (
            ('verify_issue_1700_route_inventory.py', 'route_inventory_unproven'),
            ('wrangler deployments list', 'candidate_ownership_unproven'),
            ('wrangler versions view', 'candidate_ownership_unproven'),
            ('verify-candidate', 'candidate_ownership_unproven'),
            ('issue_1700_rollback_quiescence.py', 'first_quiescence_unproven'),
        )
        for fail_on, reason in cases:
            with self.subTest(fail_on=fail_on):
                code, calls, residual = self.run_step('runtime_rollback', fail_on)
                self.assertEqual(code, 7, calls)
                self.assertTrue(any('issue_1700_http_bootstrap.mjs cleanup' in line for line in calls), calls)
                self.assertEqual(self.restores(calls), [])
                self.assertEqual(self.uploads(calls, 'rollback-runtime.toml'), [])
                self.assertEqual(residual, {'contract': 'issue1700-rollback-residual-v1', 'reason': reason,
                                            'worker_restore_attempted': False, 'active_runtime_claim': False})

    def test_cleanup_refusal_after_first_gate_writes_residual_without_restoration(self):
        code, calls, residual = self.run_step('runtime_rollback', 'issue_1700_http_bootstrap.mjs cleanup')
        self.assertNotEqual(code, 0)
        self.assertEqual(sum('issue_1700_http_bootstrap.mjs cleanup' in line for line in calls), 3)
        self.assertEqual(self.restores(calls), [])
        self.assertEqual(self.uploads(calls, 'rollback-runtime.toml'), [])
        self.assertEqual(residual, {'contract': 'issue1700-rollback-residual-v1', 'reason': 'broker_cleanup_unproven',
                                    'worker_restore_attempted': False, 'active_runtime_claim': False})

    def test_preliminary_failure_plus_cleanup_refusal_still_records_custody(self):
        # Match both the initial route read and every broker cleanup attempt.
        code, calls, residual = self.run_step('runtime_rollback', 'issue_1700')
        self.assertEqual(code, 7)
        self.assertEqual(sum('issue_1700_http_bootstrap.mjs cleanup' in line for line in calls), 3)
        self.assertEqual(self.restores(calls), [])
        self.assertEqual(self.uploads(calls, 'rollback-runtime.toml'), [])
        self.assertEqual(residual, {'contract': 'issue1700-rollback-residual-v1', 'reason': 'route_inventory_unproven',
                                    'worker_restore_attempted': False, 'active_runtime_claim': False})

    def test_restore_runs_exactly_once_on_success_and_never_without_broker_cleanup(self):
        for step_id, config in (('runtime_rollback', 'rollback-runtime.toml'), ('early_rollback', 'rollback.toml')):
            with self.subTest(step=step_id):
                code, calls, residual = self.run_step(step_id)
                self.assertEqual(code, 0, calls)
                self.assertEqual(len(self.restores(calls)), 1)
                self.assertLess(self.uploads(calls, config)[0], self.restores(calls)[0])
                self.assertIsNone(residual)
                # Cleanup refused on every bounded attempt: nothing is uploaded or restored.
                code, calls, _ = self.run_step(step_id, 'issue_1700_http_bootstrap.mjs cleanup')
                self.assertNotEqual(code, 0)
                self.assertEqual(sum('issue_1700_http_bootstrap.mjs cleanup' in line for line in calls), 3)
                self.assertFalse(any('versions deploy' in line or 'wrangler deploy --' in line for line in calls), calls)
                # One transient cleanup failure is retried and the rollback completes (GPT #3).
                code, calls, _ = self.run_step(step_id, 'issue_1700_http_bootstrap.mjs cleanup', fail_times=1)
                self.assertEqual(code, 0, calls)
                self.assertEqual(len(self.restores(calls)), 1)

    def test_an_unverified_run_owned_candidate_is_rolled_back_by_marker_and_preimage(self):
        # GPT #1: deploy succeeded but capture/verification did not; both rollback steps skip.
        code, calls, _ = self.run_step('unverified_rollback', outcome='run_candidate_active')
        self.assertEqual(code, 0, calls)
        self.assertEqual(len(self.uploads(calls, 'rollback.toml')), 1)
        self.assertEqual(len(self.restores(calls)), 1)
        self.assertLess(max(i for i, line in enumerate(calls) if 'mjs cleanup' in line), self.restores(calls)[0])
        # The preimage is still active: clean the broker, write nothing.
        code, calls, _ = self.run_step('unverified_rollback', outcome='preimage_active')
        self.assertEqual(code, 0, calls)
        self.assertTrue(any('mjs cleanup' in line for line in calls))
        self.assertFalse(any('wrangler deploy --' in line or 'versions deploy' in line for line in calls), calls)
        # Not attributable to this run: fail closed, no write.
        code, calls, _ = self.run_step('unverified_rollback', outcome='')
        self.assertNotEqual(code, 0)
        self.assertFalse(any('wrangler deploy --' in line or 'versions deploy' in line for line in calls), calls)
        # A Container failure after the upload still restores the Worker.
        code, calls, _ = self.run_step('unverified_rollback', 'wrangler deploy --', outcome='run_candidate_active')
        self.assertNotEqual(code, 0)
        self.assertEqual(len(self.restores(calls)), 1)

    def test_rollback_wiring_bounds_budget_and_covers_every_unrestored_path(self):
        import yaml
        workflow = yaml.safe_load(Path('.github/workflows/issue-1700-container-staging-deploy.yml').read_text())
        steps = {item.get('id'): item for item in workflow['jobs']['deploy']['steps'] if item.get('id')}
        order = [item.get('id') for item in workflow['jobs']['deploy']['steps']]
        for step_id in ('early_rollback', 'runtime_rollback'):
            run = steps[step_id]['run']
            # Bounded wait inside a step budget that leaves room for the restore (Claude minor).
            self.assertEqual(run.count('CONTAINER_WAIT_TIMEOUT_MS=420000'), 1)
            self.assertGreaterEqual(steps[step_id]['timeout-minutes'], 30)
            # Runtime custody precedes reads; restoration opens only after cleanup.
            if step_id == 'runtime_rollback':
                self.assertLess(run.index('trap finish_rollback EXIT'), run.index('verify_issue_1700_route_inventory.py'))
                self.assertLess(run.index('broker_cleanup\n'), run.index('worker_restore_permitted=1\n'))
            else:
                self.assertLess(run.index('broker_cleanup\n'), run.index('trap finish_rollback EXIT'))
            self.assertLess(run.index('trap finish_rollback EXIT'), run.index('read-container-state'))
            self.assertLess(run.index('trap finish_rollback EXIT'), run.index('verify-container-digest'))
        # The runtime probe CLI honours that budget (its contract still caps it at 600000 ms).
        probe_cli = Path('scripts/issue_1700_runtime_probe.mjs').read_text()
        self.assertIn('const budget = process.env.CONTAINER_WAIT_TIMEOUT_MS;', probe_cli)
        self.assertIn('timeoutMs: budget === undefined ? 600_000 : Number(budget),', probe_cli)
        runtime = steps['runtime_rollback']['run']
        gate = runtime.index('ROLLBACK_CONTAINER_RESTORE_ATTEMPTED=1 python3 scripts/issue_1700_rollback_quiescence.py')
        self.assertLess(runtime.rindex('worker_restore_permitted=0', 0, gate), gate)
        self.assertLess(gate, runtime.index('worker_restore_permitted=1\nrestore_worker_preimage\n'))
        # A failed attempt waits out its hard stop before the runtime rollback (lead Q2).
        wait = steps['attempt_quiescence']
        self.assertEqual(order.index('attempt_quiescence') + 1, order.index('runtime_rollback'))
        self.assertIn("steps.runtime_probe.outcome == 'failure'", wait['if'])
        self.assertTrue(wait['continue-on-error'])
        self.assertIn('issue_1700_http_bootstrap.mjs await_quiescence', wait['run'])
        # The unverified path is exactly complementary to the verified rollbacks.
        unverified = steps['unverified_rollback']
        self.assertIn("steps.verify_candidate.outcome != 'success'", unverified['if'])
        self.assertIn("steps.verify_candidate.outcome == 'success'", steps['early_rollback']['if'])
        self.assertIn("steps.verify_candidate.outcome == 'success'", steps['runtime_rollback']['if'])
        never = next(item for item in workflow['jobs']['deploy']['steps']
                     if item.get('name') == 'Clean owned bootstrap when candidate execution was never reached')
        self.assertIn("steps.unverified_rollback.outcome == 'skipped'", never['if'])
