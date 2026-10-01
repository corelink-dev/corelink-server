"""No provider calls: exercise exact completion admission and fail-closed sequencing."""
import copy
import json
import unittest
import subprocess
from pathlib import Path

from scripts import complete_issue_1700_existing as completion
from tests import test_staging_deployment_guard as fixtures


def snapshot():
    data = fixtures.existing_evidence()
    substitutions = {
        fixtures.ROLLOUT_SHA: completion.PIN['rollout_sha'],
        fixtures.ROLLOUT_RUN_ID: completion.PIN['rollout_run_id'],
        fixtures.ACTIVE_DEPLOYMENT: completion.PIN['deployment_id'],
        fixtures.ACTIVE_VERSION: completion.PIN['version_id'],
        fixtures.PREIMAGE_DEPLOYMENT: completion.PIN['preimage_deployment_id'],
        fixtures.PREIMAGE_VERSION: completion.PIN['preimage_version_id'],
        fixtures.IMAGE_DIGEST: completion.PIN['image_digest'],
    }
    text = json.dumps(data)
    for before, after in substitutions.items():
        text = text.replace(before, after)
    data = json.loads(text)
    data['deployments'][0]['annotations']['workers/message'] = data['version']['annotations']['workers/message'][:48] + "..."
    data['containers'] = [{'id': completion.APP, 'name': 'corelink-staging-corelinkserver',
                           'version': 9, 'exact_application_health_verified': True, 'image': f"registry.cloudflare.com/{completion.ACCOUNT}/corelink-staging-corelinkserver@{completion.PIN['image_digest']}"}]
    data['schedules'], data['tails'] = [], []
    return data


def validate(data):
    return completion.validate_state(data, data['workflow_run'], data['rollout_log'], 'a' * 40)


class CompletionTests(unittest.TestCase):
    def test_exact_pin_and_all_resource_negative_controls(self):
        data = snapshot()
        self.assertEqual(validate(data)['container_application_version'], 9)
        for field, value in [('id', 'wrong'), ('name', 'wrong'), ('version', 8), ('exact_application_health_verified', False), ('image', 'wrong')]:
            bad = copy.deepcopy(data)
            bad['containers'][0][field] = value
            with self.assertRaises(Exception):
                validate(bad)
        for mutate in [
            lambda d: d['version']['annotations'].update({'workers/message': 'wrong'}),
            lambda d: d['workflow_run'].update({'head_sha': 'b' * 40}),
            lambda d: d['routes'].update({'canonical_staging_route_count': 1}),
            lambda d: d.update({'schedules': [{'cron': '*/2 * * * *'}]}),
            lambda d: d.update({'tails': [{'id': 'other'}]}),
        ]:
            bad = copy.deepcopy(data)
            mutate(bad)
            with self.assertRaises(Exception):
                validate(bad)

    def test_preflight_failure_never_runs_probe_or_deploy(self):
        def rejected(_):
            raise ValueError('secret must not appear')
        result = completion.complete(snapshot, lambda: self.fail('probe called'), rejected)
        self.assertEqual(result['failed_stage'], 'preflight')
        self.assertFalse(result['deploy_attempted'])
        self.assertNotIn('secret', json.dumps(result))

    def test_probe_failure_keeps_explicit_safe_residual_without_blind_rollback(self):
        def failed():
            raise ValueError('provider secret')
        result = completion.complete(snapshot, failed, validate)
        self.assertEqual(result['outcome'], 'failed')
        self.assertEqual(result['residual_state'], 'current_readback_candidate_route_free_no_schedule_or_tail')
        self.assertEqual(result['queued_event_state'], 'unresolved')
        self.assertFalse(result['rollback_attempted'])
        self.assertIn('rollback_unsafe_reason', result)
        self.assertNotIn('provider secret', json.dumps(result))

    def test_success_requires_fresh_postflight_and_drift_fails_closed(self):
        result = completion.complete(snapshot, lambda: {'outcome': 'pass'}, validate)
        self.assertEqual(result['outcome'], 'pass')
        calls = 0
        def drift():
            nonlocal calls
            calls += 1
            data = snapshot()
            if calls > 1:
                data['containers'][0]['version'] = 7
            return data
        result = completion.complete(drift, lambda: {'outcome': 'pass'}, validate)
        self.assertEqual(result['outcome'], 'failed')
        self.assertEqual(result['failed_stage'], 'postflight')
        self.assertEqual(result['residual_state'], 'unverified_or_drifted_operator_readback_required')

    def test_incomplete_or_stale_runtime_receipt_is_rejected(self):
        window = completion.V5_WINDOW
        receipt = {'contract': 'corelink-staging-runtime-deployment-proof-v1',
                   'worker_release': completion.PIN['rollout_sha'], 'container_image_digest': completion.PIN['image_digest'],
                   'probe_nonce': window['nonce'], 'schedule_restored_empty': True, 'tail_deleted': True,
                   'receipt': {'contract': 'corelink-staging-d1-binding-runtime-v1', 'outcome': 'pass',
                     'probe_nonce': window['nonce'], 'worker_release': completion.PIN['rollout_sha'],
                     'scheduled_time_ms': window['starts_ms'] + 60000,
                     'old_probe_release': '0f785fb9b096afe01247f1057d46377b9f604f13',
                     'old_probe_retired': True, 'old_probe_tables_absent': True, 'v4_probe_catalog_absent': True,
                     **dict.fromkeys(('parameterized_select', 'failed_batch_observed', 'rollback_absence_verified',
                         'probe_table_dropped', 'd1_binding_intercepted', 'authorization_absent', 'cf_api_token_absent'), True)}}
        completion.validate_runtime(receipt, window['starts_ms'], window['starts_ms'] + 60000)
        for key, value in [('probe_nonce', 'wrong'), ('old_probe_release', 'wrong'), ('old_probe_retired', False), ('old_probe_tables_absent', False), ('v4_probe_catalog_absent', False), ('probe_table_dropped', False), ('scheduled_time_ms', window['starts_ms'] - 1)]:
            bad = copy.deepcopy(receipt)
            bad['receipt'][key] = value
            with self.assertRaises(RuntimeError):
                completion.validate_runtime(bad, window['starts_ms'], window['starts_ms'] + 60000)

    def test_timeout_preserves_only_safe_partial_diagnostics_and_never_passes(self):
        message = b'issue-1700 runtime probe failed {"stage":"receipt_wait","code":"receipt_timeout"}\n'
        def timed_out(*args, **kwargs):
            self.assertEqual(kwargs['timeout'], 22 * 60)
            raise subprocess.TimeoutExpired(args[0], 22 * 60,
                output=b'{"outcome":"pass","secret":"do-not-echo"}', stderr=message)
        result = completion.complete(snapshot, lambda: completion.run_runtime_process({}, 0, runner=timed_out), validate)
        self.assertEqual(result['outcome'], 'failed')
        self.assertEqual(result['runtime_failure'], {'code': 'subprocess_timeout', 'timeout_seconds': 1320,
            'host_diagnostics': [{'stage': 'receipt_wait', 'code': 'receipt_timeout'}]})
        self.assertNotIn('do-not-echo', json.dumps(result))
        self.assertEqual(result['residual_state'], 'current_readback_candidate_route_free_no_schedule_or_tail')
        self.assertEqual(result['queued_event_state'], 'unresolved')

    def test_nonzero_exit_keeps_stage_and_strips_arbitrary_stderr(self):
        message = 'issue-1700 runtime probe failed {"stage":"tail_cleanup","code":"api_failure","http_status":503,"secret":"hidden"}\n'
        result = subprocess.CompletedProcess([], 1, '', 'private tail URL\n' + message)
        with self.assertRaises(completion.ProbeProcessFailure) as raised:
            completion.run_runtime_process({}, 0, runner=lambda *a, **k: result)
        self.assertEqual(raised.exception.details['host_diagnostics'],
            [{'stage': 'tail_cleanup', 'code': 'api_failure', 'http_status': 503}])
        self.assertEqual(completion.host_diagnostics('issue-1700 runtime probe failed {"stage":"secret","code":"secret"}'), [])
        self.assertEqual(completion.host_diagnostics(b'issue-1700 runtime probe failed broken'), [])

    def test_fixed_v5_window_requires_full_75_minute_reserve(self):
        completion.require_completion_budget(1790791200000)
        for now in [1790791200000 - 1, 1790812740000 - 75 * 60_000, 1790812740000]:
            with self.assertRaises(RuntimeError):
                completion.require_completion_budget(now)

    def test_workflow_separates_credentials_and_gates_completion(self):
        workflow = Path('.github/workflows/issue-1700-container-staging-deploy.yml').read_text()
        readonly = workflow.split('      - name: Validate existing route-free rollout without mutation', 1)[1].split('      - name:', 1)[0]
        self.assertIn('secrets.STAGING_CF_ROUTE_READ_TOKEN', readonly)
        job = workflow.split('\n  complete_existing:\n', 1)[1]
        for required in ["inputs.operation == 'complete_existing'", "github.ref_protected", 'environment: staging', 'complete-existing-staging-1700', 'actions: read']:
            self.assertIn(required, job)
        self.assertNotIn('wrangler deploy', job)


if __name__ == '__main__':
    unittest.main()
