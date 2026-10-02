#!/usr/bin/env python3
"""Do not restore pre-retirement Worker code while a probe trigger/tail remains."""
import json
import os
from pathlib import Path
import re
import subprocess
import time
import urllib.request

API = 'https://api.cloudflare.com/client/v4/accounts/6a1fc1c626fc2628823e60b9db01f5cd/workers/scripts/corelink-staging'
HTTP_ORIGIN = 'https://corelink-staging.gmhelmold.workers.dev'
HTTP_NONCE = 'issue-1700-recovery-20261002-v15'
HTTP_START_MS, HTTP_LAST_ENTRY_MS, HTTP_EXPIRY_MS = 1790964000000, 1790971200000, 1790975700000
OLD_RELEASES = {'v8': '7d18bcfc450db97b1b987923050b92971da530a8',
                'v9': '5da497051f0b11dbfc8b87d1dfa8e753304e2719'}
BROKER_STATUS_CONTRACT = 'issue1700-broker-status-observation-v1'
BROKER_LIFETIME_MS = 45 * 60_000
BROKER_STATUS_MAX_AGE_MS = 5_000
BROKER_PROBE_RESERVE_MS = 21 * 60_000 + 8 * 60_000 + 90_000


def read_broker_status(directory, *, runner=subprocess.run, now=lambda: int(time.time() * 1000)):
    """Fresh local IPC only; do not read a stale broker ledger as current RAM state."""
    requested = now()
    result = runner(['node', str(Path(__file__).with_name('issue_1700_http_bootstrap.mjs').resolve()),
                     'status', str(directory)], capture_output=True, text=True, timeout=5,
                    env={key: os.environ[key] for key in ('PATH', 'HOME', 'LANG') if key in os.environ})
    observed = now()
    if result.returncode or not isinstance(result.stdout, str) or len(result.stdout.encode()) > 32768:
        raise ValueError('broker status unproven')
    return {'contract': BROKER_STATUS_CONTRACT, 'requested_at_ms': requested,
            'observed_at_ms': observed, 'broker': json.loads(result.stdout)}


def never_execute_status(observation, *, operation_id, release, image_digest, candidate_deployment_id,
                         candidate_version_id, preimage_deployment_id, preimage_version_id, now_ms):
    """Permit only a live, fenced reserve denial or its completed owned cleanup."""
    def exact(value, keys):
        return isinstance(value, dict) and set(value) == set(keys.split())

    def integer(value):
        return type(value) is int and abs(value) <= 9007199254740991

    def uuid(value):
        return isinstance(value, str) and re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}', value)

    keys = ('contract operation_id worker_release started_at_ms expires_at_ms state secret_name '
            'secret_put_attempted secret_put_confirmed secret_put_at_ms subdomain_enable_attempted subdomain_enabled '
            'subdomain_restore_attempted subdomain_restored secret_delete_attempted secret_deleted rollback_safe '
            'cleanup_basis probe_command_seen admission_closed preimage post_secret post_delete candidate preimage_bindings failure pid')
    if (not exact(observation, 'contract requested_at_ms observed_at_ms broker') or
        observation['contract'] != BROKER_STATUS_CONTRACT or
        not all(integer(value) for value in (now_ms, observation['requested_at_ms'], observation['observed_at_ms']))):
        return False
    broker = observation['broker']
    if (not exact(broker, keys) or broker['contract'] != 'corelink-staging-http-bootstrap-v1' or
        not isinstance(operation_id, str) or not re.fullmatch(r'[1-9][0-9]{0,19}', operation_id) or
        not isinstance(release, str) or not re.fullmatch(r'[0-9a-f]{40}', release) or release in OLD_RELEASES.values() or
        not isinstance(image_digest, str) or not re.fullmatch(r'sha256:[0-9a-f]{64}', image_digest) or
        broker['operation_id'] != operation_id or broker['worker_release'] != release or
        not all(integer(broker[key]) for key in ('started_at_ms', 'expires_at_ms', 'secret_put_at_ms', 'pid')) or broker['pid'] < 2 or
        broker['expires_at_ms'] != broker['started_at_ms'] + BROKER_LIFETIME_MS or
        not broker['started_at_ms'] <= observation['requested_at_ms'] <= observation['observed_at_ms'] <= now_ms < broker['expires_at_ms'] or
        now_ms - observation['observed_at_ms'] > BROKER_STATUS_MAX_AGE_MS or
        observation['observed_at_ms'] - observation['requested_at_ms'] > BROKER_STATUS_MAX_AGE_MS or
        not broker['started_at_ms'] <= broker['secret_put_at_ms'] <= observation['observed_at_ms'] or
        broker['secret_name'] != 'CORELINK_ADMIN_AUTH_KEY' or broker['secret_put_attempted'] is not True or
        broker['secret_put_confirmed'] is not True or broker['subdomain_enable_attempted'] is not True or
        broker['admission_closed'] is not True or broker['probe_command_seen'] is not False or
        broker['failure'] is not None):
        return False
    candidate = broker['candidate']
    preimage = broker['preimage']
    post_secret = broker['post_secret']
    if (not all(uuid(value) for value in (candidate_deployment_id, candidate_version_id, preimage_deployment_id, preimage_version_id)) or
        candidate_deployment_id == preimage_deployment_id or candidate_version_id == preimage_version_id or
        not exact(candidate, 'operation_id candidate_deployment_id candidate_version_id worker_release image_digest') or
        candidate != dict(operation_id=operation_id, candidate_deployment_id=candidate_deployment_id,
                          candidate_version_id=candidate_version_id, worker_release=release, image_digest=image_digest) or
        not exact(preimage, 'deployment_id version_id created_at_ms subdomain') or
        preimage['deployment_id'] != preimage_deployment_id or preimage['version_id'] != preimage_version_id or
        not integer(preimage['created_at_ms']) or preimage['created_at_ms'] > broker['started_at_ms'] or
        not exact(preimage['subdomain'], 'enabled previews_enabled') or
        preimage['subdomain']['enabled'] is not False or preimage['subdomain']['previews_enabled'] is not False or
        not exact(post_secret, 'deployment_id version_id created_at_ms') or
        not uuid(post_secret['deployment_id']) or not uuid(post_secret['version_id']) or
        post_secret['deployment_id'] in (preimage_deployment_id, candidate_deployment_id) or
        post_secret['version_id'] in (preimage_version_id, candidate_version_id) or
        not integer(post_secret['created_at_ms']) or
        not broker['secret_put_at_ms'] // 1000 * 1000 <= post_secret['created_at_ms'] <= observation['observed_at_ms']):
        return False
    bindings = broker['preimage_bindings']
    if not isinstance(bindings, list) or len(bindings) > 128:
        return False
    names = set()
    for binding in bindings:
        if (not exact(binding, 'name type') or not isinstance(binding['name'], str) or
            not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,127}', binding['name']) or
            not isinstance(binding['type'], str) or not re.fullmatch(r'[a-z][a-z0-9_]{0,63}', binding['type']) or
            binding['name'] in names or binding['name'] == 'CORELINK_ADMIN_AUTH_KEY'):
            return False
        names.add(binding['name'])
    if broker['state'] == 'enabled':
        return (broker['expires_at_ms'] - observation['observed_at_ms'] < BROKER_PROBE_RESERVE_MS and
                broker['subdomain_enabled'] is True and broker['rollback_safe'] is False and
                broker['cleanup_basis'] is None and broker['post_delete'] is None and
                all(broker[key] is False for key in ('subdomain_restore_attempted', 'subdomain_restored',
                                                   'secret_delete_attempted', 'secret_deleted')))
    if broker['state'] != 'cleaned' or broker['cleanup_basis'] != 'never_execute' or broker['subdomain_enabled'] is not False:
        return False
    post_delete = broker['post_delete']
    return (all(broker[key] is True for key in ('rollback_safe', 'subdomain_restore_attempted', 'subdomain_restored',
                                              'secret_delete_attempted', 'secret_deleted')) and
            exact(post_delete, 'deployment_id version_id created_at_ms') and
            uuid(post_delete['deployment_id']) and uuid(post_delete['version_id']) and
            post_delete['deployment_id'] not in (preimage_deployment_id, candidate_deployment_id, post_secret['deployment_id']) and
            post_delete['version_id'] not in (preimage_version_id, candidate_version_id, post_secret['version_id']) and
            integer(post_delete['created_at_ms']) and post_secret['created_at_ms'] <= post_delete['created_at_ms'] <= observation['observed_at_ms'])


def complete_http_proof(attempt, wrapper, expected_release, expected_image_digest, now_ms):
    """A strict authenticated HTTP proof, independent of empty trigger inventory."""
    attempt_keys = set('contract carrier origin worker_release probe_nonce scheduled_time_ms started_at_ms deadline_ms transport_deadline_ms request_attempted'.split())
    envelope_keys = set('contract carrier worker_release probe_nonce status rollback_safe native_receipt v8_cleanup v9_cleanup'.split())
    native_keys = set('old_probe_release old_probe_retired old_probe_tables_absent v5_probe_release v5_probe_retired v5_probe_tables_absent v5_prior_execution v4_probe_catalog_absent contract probe_nonce outcome worker_release scheduled_time_ms parameterized_select failed_batch_observed rollback_absence_verified probe_table_dropped d1_binding_intercepted authorization_absent cf_api_token_absent'.split())
    cleanup_keys = set('contract old_release old_nonce worker_release prior_execution prior_admission_present container_stopped alarm_absent tables_absent completed_at_ms'.split())
    wrapper_keys = set('contract carrier account_id worker_name workflow_sha worker_release container_image_digest probe_nonce origin http_proof receipt schedules_empty tails_empty'.split())

    def exact(value, keys):
        return isinstance(value, dict) and set(value) == keys

    def integer(value):
        return type(value) is int and abs(value) <= 9007199254740991

    if (not exact(wrapper, wrapper_keys) or wrapper['contract'] != 'corelink-staging-runtime-deployment-proof-v1' or
        wrapper['carrier'] != 'authenticated_http' or wrapper['account_id'] != '6a1fc1c626fc2628823e60b9db01f5cd' or
        wrapper['worker_name'] != 'corelink-staging' or wrapper['workflow_sha'] != expected_release or
        wrapper['worker_release'] != expected_release or wrapper['probe_nonce'] != HTTP_NONCE or
        wrapper['origin'] != HTTP_ORIGIN or wrapper['schedules_empty'] is not True or wrapper['tails_empty'] is not True or
        not isinstance(expected_image_digest, str) or not re.fullmatch(r'sha256:[0-9a-f]{64}', expected_image_digest) or
        wrapper['container_image_digest'] != expected_image_digest):
        return False
    proof = wrapper['http_proof']
    if (not exact(attempt, attempt_keys) or not exact(proof, envelope_keys) or
        not isinstance(expected_release, str) or not re.fullmatch(r'[0-9a-f]{40}', expected_release) or
        expected_release in OLD_RELEASES.values() or not integer(now_ms) or
        not re.fullmatch(r'https://corelink-staging\.[a-z0-9-]+\.workers\.dev', HTTP_ORIGIN) or
        attempt['origin'] != HTTP_ORIGIN or attempt['contract'] != 'corelink-staging-http-attempt-v1' or
        attempt['carrier'] != 'authenticated_http' or attempt['request_attempted'] is not True or
        attempt['worker_release'] != expected_release or attempt['probe_nonce'] != HTTP_NONCE or
        not all(integer(attempt[key]) for key in ('started_at_ms', 'scheduled_time_ms', 'deadline_ms', 'transport_deadline_ms'))):
        return False
    started, scheduled = attempt['started_at_ms'], attempt['scheduled_time_ms']
    if (not HTTP_START_MS <= started < HTTP_LAST_ENTRY_MS or scheduled != started // 120000 * 120000 or
        scheduled < HTTP_START_MS or scheduled > now_ms or
        attempt['deadline_ms'] != started + 1200000 or attempt['transport_deadline_ms'] != started + 1260000 or
        attempt['transport_deadline_ms'] >= HTTP_EXPIRY_MS or
        proof['contract'] != 'corelink-staging-d1-http-proof-v1' or proof['carrier'] != 'authenticated_http' or
        proof['worker_release'] != expected_release or proof['probe_nonce'] != HTTP_NONCE or
        proof['status'] != 'complete' or proof['rollback_safe'] is not True):
        return False
    native = proof['native_receipt']
    flags = 'old_probe_retired old_probe_tables_absent v5_probe_retired v5_probe_tables_absent v4_probe_catalog_absent parameterized_select failed_batch_observed rollback_absence_verified probe_table_dropped d1_binding_intercepted authorization_absent cf_api_token_absent'.split()
    if (not exact(native, native_keys) or native['contract'] != 'corelink-staging-d1-binding-runtime-v1' or
        native['outcome'] != 'pass' or native['worker_release'] != expected_release or native['probe_nonce'] != HTTP_NONCE or
        not integer(native['scheduled_time_ms']) or native['scheduled_time_ms'] != scheduled or
        native['old_probe_release'] != '0f785fb9b096afe01247f1057d46377b9f604f13' or
        native['v5_probe_release'] != 'cc32b3d819181bf9175e795868f66212aa5456c1' or
        native['v5_prior_execution'] != 'unknown' or not all(native[key] is True for key in flags)):
        return False
    if json.dumps(wrapper['receipt'], sort_keys=True) != json.dumps(native, sort_keys=True):
        return False
    for version in ('v8', 'v9'):
        cleanup = proof[version + '_cleanup']
        if (not exact(cleanup, cleanup_keys) or cleanup['contract'] != f'corelink-staging-{version}-cleanup-v1' or
            cleanup['old_release'] != OLD_RELEASES[version] or cleanup['old_nonce'] != 'issue-1700-recovery-20261001-' + version or
            cleanup['worker_release'] != expected_release or cleanup['prior_execution'] != 'unknown' or
            type(cleanup['prior_admission_present']) is not bool or
            not all(cleanup[key] is True for key in ('container_stopped', 'alarm_absent', 'tables_absent')) or
            not integer(cleanup['completed_at_ms']) or not started <= cleanup['completed_at_ms'] <= now_ms or
            not HTTP_START_MS <= cleanup['completed_at_ms'] < HTTP_EXPIRY_MS or
            cleanup['completed_at_ms'] >= attempt['deadline_ms']):
            return False
    return True


def read(path):
    if path not in ('/schedules', '/tails'):
        raise ValueError('unapproved read')
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args, **kwargs):
            return None
    request = urllib.request.Request(API + path, headers={
        'Authorization': 'Bearer ' + os.environ['WORKER_API_TOKEN']})
    with urllib.request.build_opener(NoRedirect).open(request, timeout=30) as response:
        raw = response.read(65537)
        if response.status != 200 or len(raw) > 65536:
            raise ValueError('bounded read failed')
        return json.loads(raw)


def inspect(read_api=read, *, http_attempt=None, http_proof=None, expected_release=None, expected_image_digest=None,
            http_required=False, now_ms=None, broker_status_reader=None, operation_id=None,
            candidate_deployment_id=None, candidate_version_id=None,
            preimage_deployment_id=None, preimage_version_id=None):
    receipt = {'contract': 'issue1700-preimage-rollback-quiescence-v1',
               'rollback_allowed': False, 'rollback_attempted': False,
               'schedules_empty': False, 'tails_empty': False,
               'http_proof_required': http_required or http_attempt is not None or http_proof is not None,
               'http_complete_and_safe': False, 'http_never_executed': False}
    try:
        schedules = read_api('/schedules')
        tails = read_api('/tails')
        if (schedules.get('success') is not True or tails.get('success') is not True or
            not isinstance(schedules.get('result'), dict) or
            not isinstance(schedules['result'].get('schedules'), list) or
            not isinstance(tails.get('result'), list)):
            raise ValueError('inventory envelope rejected')
        receipt['schedules_empty'] = schedules['result']['schedules'] == []
        receipt['tails_empty'] = tails['result'] == []
        inventories_empty = receipt['schedules_empty'] and receipt['tails_empty']
        receipt['http_complete_and_safe'] = complete_http_proof(
            http_attempt, http_proof, expected_release, expected_image_digest,
            int(time.time() * 1000) if now_ms is None else now_ms)
        if (receipt['http_proof_required'] and not receipt['http_complete_and_safe'] and
            http_attempt is None and broker_status_reader is not None):
            observation = broker_status_reader()
            receipt['http_never_executed'] = never_execute_status(observation,
                operation_id=operation_id, release=expected_release, image_digest=expected_image_digest,
                candidate_deployment_id=candidate_deployment_id, candidate_version_id=candidate_version_id,
                preimage_deployment_id=preimage_deployment_id, preimage_version_id=preimage_version_id,
                now_ms=int(time.time() * 1000) if now_ms is None else now_ms)
            if receipt['http_never_executed']:
                receipt['_broker_observation'] = observation
        receipt['rollback_allowed'] = inventories_empty and (
            not receipt['http_proof_required'] or receipt['http_complete_and_safe'] or receipt['http_never_executed'])
        receipt['reason'] = ('probe_activity_remains' if not inventories_empty else
                             'http_execution_or_cleanup_unproven' if not receipt['rollback_allowed'] else 'quiescent')
    except Exception:
        receipt['reason'] = 'quiescence_unproven'
    return receipt


def main():
    directory = Path(os.environ['RUNNER_TEMP'])
    def artifact(name):
        path = directory / name
        if not path.exists():
            return None
        try:
            raw = path.read_bytes()
            if len(raw) > 16384:
                raise ValueError('oversize artifact')
            return json.loads(raw)
        except Exception:
            return {'invalid': True}
    receipt = inspect(http_attempt=artifact('staging-http-broker/staging-http-probe-attempt.json'),
                      http_proof=artifact('staging-runtime-probe-receipt.json'),
                      expected_release=os.environ.get('EXPECTED_SHA'),
                      expected_image_digest=os.environ.get('CANDIDATE_CONTAINER_IMAGE_DIGEST'),
                      http_required=os.environ.get('HTTP_PROBE_STEP_OUTCOME') not in (None, '', 'skipped'),
                      broker_status_reader=lambda: read_broker_status(directory / 'staging-http-broker'),
                      operation_id=os.environ.get('GITHUB_RUN_ID'),
                      candidate_deployment_id=os.environ.get('CANDIDATE_DEPLOYMENT_ID'),
                      candidate_version_id=os.environ.get('CANDIDATE_VERSION_ID'),
                      preimage_deployment_id=os.environ.get('PREIMAGE_DEPLOYMENT_ID'),
                      preimage_version_id=os.environ.get('PREIMAGE_VERSION_ID'))
    observation = receipt.pop('_broker_observation', None)
    if observation is not None:
        (directory / 'staging-http-broker-status.json').write_text(json.dumps(observation, sort_keys=True) + '\n')
        receipt['broker_status_observed_at_ms'] = observation['observed_at_ms']
    receipt["rollback_attempted"] = os.environ.get("ROLLBACK_CONTAINER_RESTORE_ATTEMPTED") == "1"
    receipt["preimage_worker_restore_attempted"] = False
    path = directory / 'staging-rollback-quiescence.json'
    path.write_text(json.dumps(receipt, indent=2) + '\n')
    print(json.dumps(receipt))
    return 0 if receipt['rollback_allowed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
