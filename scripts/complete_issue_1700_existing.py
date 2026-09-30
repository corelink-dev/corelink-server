#!/usr/bin/env python3
"""Protected, one-shot completion of the exact isolated #1700 rollout; no deploy."""
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import urllib.request

try:
    from .verify_issue_1700_existing_deployment import validate_existing_deployment
    from .verify_issue_1700_route_inventory import verify_route_free
except ImportError:
    from verify_issue_1700_existing_deployment import validate_existing_deployment
    from verify_issue_1700_route_inventory import verify_route_free

PIN = {
    'rollout_sha': '0f785fb9b096afe01247f1057d46377b9f604f13',
    'rollout_run_id': '36646546021',
    'deployment_id': '8753a6ba-8ee1-46d8-8d11-74aea7778a16',
    'version_id': '516d7e11-c366-4ebf-b84b-eec9a4861446',
    'preimage_deployment_id': 'fd1468fe-ce65-4f05-9527-9fc32c71ee0b',
    'preimage_version_id': 'd787acbc-666b-4e2f-87b3-0e93a3f6393b',
    'image_digest': 'sha256:e44e139e6bb03c019445ee0d5106ce005210c8d9f945c81bfab9d13ab847eda3',
}
APP = 'a033fb81-6388-47d9-9049-0b6942778055'
PREIMAGE_DIGEST = 'sha256:803930be734d502979064c08f6442c26724d6091ccc972ed48d0e69f693f1c32'
ACCOUNT = '6a1fc1c626fc2628823e60b9db01f5cd'
API = f'https://api.cloudflare.com/client/v4/accounts/{ACCOUNT}/workers/scripts/corelink-staging'


def command(args, *, env=None, timeout=120):
    result = subprocess.run(args, capture_output=True, text=True, env=env, timeout=timeout)
    if result.returncode:
        raise RuntimeError('bounded command failed')
    return result.stdout


def worker_read(path):
    request = urllib.request.Request(API + path, headers={
        'Authorization': 'Bearer ' + os.environ['CLOUDFLARE_API_TOKEN']})
    with urllib.request.urlopen(request, timeout=30) as response:
        body = json.load(response)
    if body.get('success') is not True:
        raise RuntimeError('Worker readback failed')
    return body


def validate_state(state, run, log, current_sha):
    receipt = validate_existing_deployment(
        state['deployments'], state['version'], state['settings'],
        json.loads(Path('infra/staging/topology.json').read_text()), state['routes'],
        run, log, current_sha=current_sha, **PIN)
    matches = [a for a in state['containers'] if a.get('id') == APP or a.get('name') == 'corelink-staging-corelinkserver']
    if len(matches) != 1 or matches[0].get('id') != APP or matches[0].get('name') != 'corelink-staging-corelinkserver' or matches[0].get('version') != 6 or matches[0].get('image') != f"registry.cloudflare.com/{ACCOUNT}/corelink-staging-corelinkserver@{PIN['image_digest']}":
        raise RuntimeError('exact candidate Container changed')
    if state['schedules'] != [] or state['tails'] != []:
        raise RuntimeError('schedule or tail inventory is not empty')
    return {**receipt, 'container_application_id': APP, 'container_application_version': 6,
            'schedules_empty': True, 'tails_empty': True}


def validate_runtime(receipt, started_ms, now_ms):
    window = json.loads(Path('crates/corelink-container/src/routes/staging_d1_probe_window.json').read_text())
    native = receipt.get('receipt', {})
    if (receipt.get('contract') != 'corelink-staging-runtime-deployment-proof-v1'
        or receipt.get('worker_release') != PIN['rollout_sha']
        or receipt.get('container_image_digest') != PIN['image_digest']
        or receipt.get('probe_nonce') != window['nonce']
        or receipt.get('schedule_restored_empty') is not True or receipt.get('tail_deleted') is not True
        or native.get('contract') != 'corelink-staging-d1-binding-runtime-v1'
        or native.get('outcome') != 'pass' or native.get('probe_nonce') != window['nonce']
        or native.get('worker_release') != PIN['rollout_sha']
        or type(native.get('scheduled_time_ms')) is not int
        or not started_ms <= native['scheduled_time_ms'] <= now_ms < window['expires_ms']
        or not all(native.get(k) is True for k in ('parameterized_select', 'failed_batch_observed',
            'rollback_absence_verified', 'probe_table_dropped', 'd1_binding_intercepted',
            'authorization_absent', 'cf_api_token_absent'))):
        raise RuntimeError('runtime receipt rejected')
    return receipt


def complete(collect, probe, validate):
    """A missing runtime/cleanup receipt never becomes a success or an auto-rollback."""
    result = {'contract': 'issue-1700-existing-runtime-completion-v1', 'outcome': 'failed',
              'pin': PIN, 'preimage_container_version': 5, 'preimage_image_digest': PREIMAGE_DIGEST,
              'deploy_attempted': False, 'probe_attempted': False, 'rollback_attempted': False}
    stage = 'preflight'
    try:
        result['before'] = validate(collect())
        stage = 'runtime_probe'
        result['probe_attempted'] = True
        result['runtime'] = probe()
        stage = 'postflight'
        result['after'] = validate(collect())
        result['outcome'] = 'pass'
    except Exception:
        # Never print raw provider errors, subprocess output, credentials or tail URLs.
        result['failed_stage'] = stage
        result['rollback_unsafe_reason'] = {'preflight': 'no_mutation_admitted', 'runtime_probe': 'native_d1_execution_or_cleanup_unproven', 'postflight': 'current_ownership_or_cleanup_unproven'}[stage]
        try:
            result['residual'] = validate(collect())
            result['residual_state'] = 'exact_candidate_route_free_no_schedule_or_tail'
        except Exception:
            result['residual_state'] = 'unverified_or_drifted_operator_readback_required'
    return result


def main():
    output = Path(os.environ['RUNNER_TEMP']) / 'issue-1700-completion-receipt.json'
    sha = os.environ.get('EXPECTED_SHA', '')
    if sha != os.environ.get('GITHUB_SHA') or sha != command(['git', 'rev-parse', 'HEAD']).strip():
        raise RuntimeError('exact checkout rejected')
    for key, expected in PIN.items():
        if os.environ.get(key.upper()) != expected:
            raise RuntimeError('completion pin rejected')
    if not os.environ.get('ROUTE_READ_TOKEN') or os.environ['ROUTE_READ_TOKEN'] == os.environ.get('CLOUDFLARE_API_TOKEN'):
        raise RuntimeError('separate route credential required')
    run = json.loads(command(['gh', 'api', f"repos/HuGR-dev/corelink-server/actions/runs/{PIN['rollout_run_id']}"]))
    log = command(['gh', 'run', 'view', PIN['rollout_run_id'], '--repo', 'HuGR-dev/corelink-server', '--log'])
    original = Path(os.environ['RUNNER_TEMP']) / 'original-rollout'
    command(['gh', 'run', 'download', PIN['rollout_run_id'], '--repo', 'HuGR-dev/corelink-server',
             '--name', 'issue-1700-route-free-deployment-' + PIN['rollout_run_id'], '--dir', str(original)])
    worker_preimage = json.loads((original / 'staging-deploy-receipt.json').read_text())['preimage']
    if worker_preimage.get('deployment_id') != PIN['preimage_deployment_id'] or worker_preimage.get('version_id') != PIN['preimage_version_id']:
        raise RuntimeError('immutable Worker preimage rejected')
    preimage = json.loads((original / 'staging-container-preimage.json').read_text())
    if preimage.get('application_id') != APP or preimage.get('application_version') != 5 or preimage.get('image_digest') != PREIMAGE_DIGEST:
        raise RuntimeError('immutable Container preimage rejected')
    config = Path(os.environ['RUNNER_TEMP']) / 'completion-root.toml'
    config.write_text(f'name = "corelink-staging"\naccount_id = "{ACCOUNT}"\ncompatibility_date = "2026-04-01"\nworkers_dev = false\n')
    wrangler = ['pnpm', 'exec', 'wrangler']

    def collect():
        return {
            'deployments': json.loads(command(wrangler + ['deployments', 'list', '--config', str(config), '--name', 'corelink-staging', '--json'])),
            'version': json.loads(command(wrangler + ['versions', 'view', PIN['version_id'], '--config', str(config), '--name', 'corelink-staging', '--json'])),
            'containers': json.loads(command(wrangler + ['containers', 'list', '--json'])),
            'settings': worker_read('/settings'),
            'routes': verify_route_free(os.environ['ROUTE_READ_TOKEN']),
            'schedules': worker_read('/schedules')['result']['schedules'],
            'tails': worker_read('/tails')['result'],
        }

    def probe():
        env = {**os.environ, 'SENTRY_RELEASE': PIN['rollout_sha'], 'EXPECTED_SHA': PIN['rollout_sha'], 'IMAGE_DIGEST': PIN['image_digest']}
        started_ms = int(time.time() * 1000)
        result = subprocess.run(['node', 'scripts/issue_1700_runtime_probe.mjs'], env=env,
                                capture_output=True, text=True, timeout=22 * 60)
        if result.returncode:
            # The host's allowlisted diagnostic remains visible; no arbitrary stderr.
            for line in result.stderr.splitlines():
                prefix = 'issue-1700 runtime probe failed '
                if line.startswith(prefix):
                    diagnostic = json.loads(line[len(prefix):])
                    if set(diagnostic) <= {'stage', 'code', 'http_status'} and all(
                        isinstance(v, int) or (isinstance(v, str) and v.replace('_', '').isalnum() and len(v) < 50)
                        for v in diagnostic.values()):
                        print(json.dumps(diagnostic), file=sys.stderr)
            raise RuntimeError('runtime probe failed')
        return validate_runtime(json.loads(result.stdout), started_ms, int(time.time() * 1000))

    receipt = complete(collect, probe, lambda state: validate_state(state, run, log, sha))
    receipt['verification_sha'] = sha
    output.write_text(json.dumps(receipt, sort_keys=True) + '\n')
    print(json.dumps(receipt, sort_keys=True))
    return 0 if receipt['outcome'] == 'pass' else 1


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception:
        print('completion failed before mutation; inspect protected step status', file=sys.stderr)
        sys.exit(1)
