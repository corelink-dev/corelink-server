#!/usr/bin/env python3
"""Inert B-063 workflow/receipt contract; never starts a provider operation.

The root-reviewed candidate and protected environment authorize execution.
This checker proves shape and negative controls, not an actual image build.
Shared commands preserve protected main 5fabd93e; the two GC host probes use
the same rootful boundary as runc, with a pre-build permission fixture.
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import re
import subprocess
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = Path('.github/workflows/container-build-push-prod.yml')
RECEIPT = Path('evidence/owner-actions/B-063/production-image-build-receipt.json')
SOURCE = '5fabd93e98d805a39319fcb6a22c9ee5267fafd4'
ACCOUNT = '6a1fc1c626fc2628823e60b9db01f5cd'
BRANCH = 'refs/heads/codex/issue-1648-hosted-build'
BUNDLE_SHA256 = 'b697295c623639734aaab737523c808fd3cc8d3046039fd94fff1744e4c317aa'
CHECKOUT = 'actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0'
UPLOAD = 'actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a'
IMAGES = tuple('corelink-' + region + '-corelinkserver-prod' for region in ('prod', 'prod-sam', 'prod-lhr', 'prod-nrt', 'prod-syd'))
SHA = re.compile(r'[0-9a-f]{40}')
DIGEST = re.compile(r'sha256:[0-9a-f]{64}')
GATES = ['size', 'credential-scan', 'runc-smoke', 'gc-dry-run', 'production-gc-fail-closed']

SHARED_STEP_SHA256 = {'Preflight — BuildKit + runc must be baked in the runner image': '53160201bc543367d81f4b0da4f082c2cc0114bda91af7af0df4f563aa796617',
 'Compute short SHA + reproducible-build args': '9ca9d276c75bb5192f5687152e92f450006123ee084939d78287ae25bfc56722',
 'Start buildkitd (rootful; the microVM is the isolation boundary)': '427192c947d43284ebccb9dd94904e78ed3bfc4b124227c4f792ca588ced668a',
 'Build prod image (buildctl → OCI) — fat-LTO, cache-mounts, native amd64': 'a8ffabc644eb411182463f3c27d2dc81a81ac406558489e661dabcdd3b873d53',
 'Extract OCI manifest + config': '1621ff5e1e7b0fff5f16f1e8d9f8ad4abb92774da193aaf97108973e241ee8c8',
 'Gate 1 — image size (CF Containers 2 GiB ceiling, daemonless)': 'e591579182927b75f3fea1f5d791146d5a79e5cce52c15cc6b4c0c684d34edce',
 'Gate 2 — CTRL-CRED-001, no credentials in image layers (daemonless)': 'd9b26cf325b321b476b4d9eb378f69a9027a3cd75a09022bd1d17c86880a0d37',
 'Gate 3 — binary smoke (runc on the extracted rootfs, daemonless)': '3bd86e0c0235cdcde48ed69d6783bee8a921939965a6c46070db5c5a0e7438c0',
 'Gate 4 — embedded GC binary is forced dry-run (daemonless)': 'b7efb802e6dac8813622f1a53b3906b2ef8630d2ba49ac5d99e834b7b840752e',
 'Gate 4b — native production GC binary is present and fail-closed': '06ba0c492702425bfe0b8dc79b1fe5148b0a14e5c515a1fbfab281170433cdaf',
 'ADR-0015 reproducibility attestation (reminder)': 'bbb37713279a35ad00a80f9b092d0c31255c3c9880af923609e864e205f284e6'}
EXTRA_STEP_SHA256 = {'build-push': {'Confirm intent': '5964bca75b8ca3492bc300540bac8847f32baebe8e2ed8861ae84d9891dbeb64',
                'Push image to the 5 CF Containers registries (daemonless, wrangler cred)': '1bfa54a757258808f0ce3d2dfee66f9842b3712a294b13db9185d11a0a4e49ab',
                'Next step (repin + deploy)': '140b684dcb037d038c019a0595ff74b8756f2fd93ca662cd2164a55be86eefc4',
                'Remove temporary registry credential file': '85f4dea3c07336e14f76b1472c68c1da702f129775286aa84f6efd09b7be9a9f'},
 'hosted-b063': {'Confirm intent': '5964bca75b8ca3492bc300540bac8847f32baebe8e2ed8861ae84d9891dbeb64',
                 'Bind reviewed workflow to frozen protected image source': 'f49ba11b285aec37bf2827ae65e5eaa930b91f9aa092f71073e787ba49b59f17',
                 'Read-only exact production registry target preflight': '1dd7bd32ef7c466773981cbfeaa8a133f8d76b273cba582a078777442a954b5a',
                 'Install canonical checksum-pinned BuildKit and runc': '2a41f45ff6ca5fd9463408623a3f6d4d5c107f94db6afe995ffcf5de7bc81bcc',
                 'Push image to the 5 CF Containers registries (daemonless, wrangler cred)': '45e1743c11cd0924f55992c3ce7fb17c0a7ab639be3a2702bb1343772daefa34',
                 'Next step (repin + deploy)': '140b684dcb037d038c019a0595ff74b8756f2fd93ca662cd2164a55be86eefc4',
                 'Emit redacted source and registry digest receipt': '61bf5d051952ce0b68de2f45866278d4ce41f4801f0a98ae8d53bbe13743cbfb',
                 'Remove temporary registry credential file': '85f4dea3c07336e14f76b1472c68c1da702f129775286aa84f6efd09b7be9a9f'}}

CONTRACT_STEP_SHA256 = {'Install inert YAML parser': '2889628c3078cf81c8264402e1b1165f16b8c574d8b260ad934f5973c2766f37',
 'Verify workflow guard and meaningful negatives': '0ffce20ed351773b021c73079a6133994a536c272164f6204eff7db893392b30',
 'Install checksum-pinned actionlint and lint only owned workflow': 'c159e4e44f7967a67049ea74ef0159f02b06fe32d5ad369699ba87eb0b53e005'}

class ContractError(ValueError):
    pass


def require(condition: bool, reason: str) -> None:
    if not condition:
        raise ContractError(reason)


def normalized(value: str) -> str:
    return ' '.join(value.split())


def validate_workflow(text: str) -> None:
    document = yaml.load(text, Loader=yaml.BaseLoader)
    require(isinstance(document, dict), 'workflow must be a mapping')
    require(set(document) == {'name', 'on', 'concurrency', 'permissions', 'jobs'}, 'workflow execution modifiers forbidden')
    require(set(document['on']) == {'workflow_dispatch'}, 'privileged workflow must be manual-only')
    inputs = document['on']['workflow_dispatch']['inputs']
    require(set(inputs) == {'confirm', 'runner_route', 'expected_sha'}, 'closed input catalog drift')
    require(inputs['runner_route']['default'] == 'corelink', 'hosted route cannot become default')
    require(inputs['runner_route']['options'] == ['corelink', 'hosted-b063', 'contract'], 'runner route catalog drift')
    require(document['permissions'] == {'contents': 'read'}, 'workflow permissions widened')
    require(document['concurrency']['group'] == 'ci-container-build-push-prod', 'duplicate build concurrency drift')
    require(document['concurrency'].get('cancel-in-progress', 'false') == 'false', 'build custody cancellation enabled')
    jobs = document['jobs']
    require(set(jobs) == {'build-push', 'hosted-b063', 'b063-contract'}, 'closed job inventory drift')
    expected_conditions = {
        'build-push': "github.repository == 'HuGR-dev/corelink-server' && github.event_name == 'workflow_dispatch' && inputs.runner_route == 'corelink' && inputs.confirm == 'build' && github.ref == 'refs/heads/main' && github.ref_protected == true",
        'hosted-b063': "github.repository == 'HuGR-dev/corelink-server' && github.event_name == 'workflow_dispatch' && inputs.runner_route == 'hosted-b063' && inputs.confirm == 'build' && github.ref == '" + BRANCH + "' && github.sha == inputs.expected_sha",
        'b063-contract': "github.repository == 'HuGR-dev/corelink-server' && github.event_name == 'workflow_dispatch' && inputs.runner_route == 'contract' && github.ref == '" + BRANCH + "' && github.sha == inputs.expected_sha",
    }
    for name, job in jobs.items():
        expected_keys = {'name', 'if', 'runs-on', 'timeout-minutes', 'steps'}
        if name != 'b063-contract':
            expected_keys.add('env')
        if name == 'hosted-b063':
            expected_keys.add('environment')
        require(set(job) == expected_keys, name + ': unexpected execution modifier')
        require(normalized(job['if']) == expected_conditions[name], name + ': exact event/ref/SHA guard drift')
        require(job['runs-on'] == ('corelink' if name == 'build-push' else 'ubuntu-24.04'), name + ': runner drift')
        require(job['timeout-minutes'] == ('5' if name == 'b063-contract' else '60'), name + ': timeout drift')
        require('continue-on-error' not in job, name + ': job failure bypass')
        if name == 'b063-contract':
            require('environment' not in job and 'env' not in job, 'contract job must have no provider credentials/environment')
        else:
            require(job['env'] == {'CLOUDFLARE_API_TOKEN': '${{ secrets.CF_API_TOKEN }}', 'CLOUDFLARE_ACCOUNT_ID': '${{ secrets.CF_ACCOUNT_ID }}'}, name + ': credential binding drift')
        if name == 'hosted-b063':
            require(job['environment'] == 'production-image-build', 'hosted provider environment drift')
        elif name == 'build-push':
            require('environment' not in job, 'legacy environment unexpectedly changed')
        checkouts = [step for step in job['steps'] if step.get('uses') == CHECKOUT]
        require(len(checkouts) == 1, name + ': exact checkout required')
        expected_checkout = {'fetch-depth': '0', 'persist-credentials': 'false'}
        if name == 'hosted-b063':
            expected_checkout['ref'] = SOURCE
        require(checkouts[0]['with'] == expected_checkout, name + ': source/credentialless checkout drift')
        if name == 'b063-contract':
            require(all('secrets.' not in str(step) for step in job['steps']), 'contract job references provider secrets')
            require([step['name'] for step in job['steps']] == ['Checkout exact candidate without credentials', *CONTRACT_STEP_SHA256], 'contract step inventory/order drift')
            require(set(checkouts[0]) == {'name', 'uses', 'with'}, 'contract checkout execution modifier')
            for step in job['steps'][1:]:
                require(set(step) == {'name', 'run'}, 'contract step execution modifier')
                require(hashlib.sha256(step['run'].encode()).hexdigest() == CONTRACT_STEP_SHA256[step['name']], 'contract command bypass')
            continue
        steps = {step['name']: step for step in job['steps']}
        require(len(steps) == len(job['steps']), name + ': duplicate step name')
        expected_steps = set(SHARED_STEP_SHA256) | set(EXTRA_STEP_SHA256[name]) | {'Checkout'}
        if name == 'hosted-b063':
            expected_steps.add('Upload redacted build receipt only')
        require(set(steps) == expected_steps, name + ': closed provider step inventory drift')
        expected_order = ['Confirm intent', 'Checkout']
        if name == 'hosted-b063':
            expected_order += ['Bind reviewed workflow to frozen protected image source', 'Read-only exact production registry target preflight', 'Install canonical checksum-pinned BuildKit and runc']
        expected_order += list(SHARED_STEP_SHA256)
        expected_order += ['Push image to the 5 CF Containers registries (daemonless, wrangler cred)', 'Next step (repin + deploy)']
        if name == 'hosted-b063':
            expected_order += ['Emit redacted source and registry digest receipt', 'Upload redacted build receipt only']
        expected_order += ['Remove temporary registry credential file']
        require(list(steps) == expected_order, name + ': source/gate/push order drift')
        hashes = SHARED_STEP_SHA256 | EXTRA_STEP_SHA256[name]
        for step_name, expected_hash in hashes.items():
            step = steps[step_name]
            require('continue-on-error' not in step, step_name + ': step failure bypass')
            expected_metadata = {'name': step_name}
            if step_name == 'Confirm intent':
                expected_metadata['env'] = {'CONFIRM_INPUT': '${{ inputs.confirm }}'}
            elif step_name == 'Compute short SHA + reproducible-build args':
                expected_metadata['id'] = 'meta'
            elif step_name == 'Bind reviewed workflow to frozen protected image source':
                expected_metadata['env'] = {'EXPECTED_WORKFLOW_SHA': '${{ inputs.expected_sha }}'}
            elif step_name == 'Emit redacted source and registry digest receipt':
                expected_metadata['env'] = {'B063_IMAGE_TAG': '${{ steps.meta.outputs.short_sha }}-r1'}
            elif step_name == 'Remove temporary registry credential file':
                expected_metadata['if'] = 'always()'
            require({key: value for key, value in step.items() if key != 'run'} == expected_metadata, step_name + ': execution metadata drift')
            expected_if = 'always()' if step_name == 'Remove temporary registry credential file' else None
            require(step.get('if') == expected_if, step_name + ': mandatory step skipped or cleanup weakened')
            require(hashlib.sha256(step['run'].encode()).hexdigest() == expected_hash, step_name + ': canonical command hash drift')
        require(set(steps['Checkout']) == {'name', 'uses', 'with'}, name + ': checkout execution modifier')
        if name == 'hosted-b063':
            upload = steps['Upload redacted build receipt only']
            require(set(upload) == {'name', 'uses', 'with'}, 'build receipt upload execution modifier')
            require(upload['uses'] == UPLOAD, 'artifact action pin drift')
            require(upload['with'] == {'name': 'b063-production-image-build-${{ github.run_id }}', 'path': 'artifacts/b063-production-image-build-receipt.json', 'if-no-files-found': 'error'}, 'artifact allowlist must exclude registry credentials')


def validate_receipt(receipt: dict, wrangler: str) -> None:
    fields = {'schema_version', 'captured_at', 'issue', 'source_sha', 'workflow_candidate_sha', 'run_id', 'run_attempt', 'account_id', 'tool_bundle_version', 'tool_bundle_sha256', 'gated_oci_config_digest', 'images', 'created_repo_expectation', 'gates', 'verdict', 'deployed', 'archive_invoked', 'd1_written'}
    require(set(receipt) == fields, 'closed receipt schema drift')
    require(receipt['schema_version'] == 1 and receipt['issue'] == 1648, 'receipt schema/issue mismatch')
    require(receipt['source_sha'] == SOURCE, 'receipt does not bind frozen protected image source')
    candidate = receipt['workflow_candidate_sha']
    require(isinstance(candidate, str) and SHA.fullmatch(candidate) is not None and candidate != SOURCE, 'workflow candidate must be distinct exact SHA')
    require(receipt['account_id'] == ACCOUNT, 'receipt account mismatch')
    require(receipt['created_repo_expectation'] in ([], [IMAGES[-1]]), 'unapproved registry repository creation expectation')
    require(receipt['tool_bundle_version'] == '2.3.5' and receipt['tool_bundle_sha256'] == BUNDLE_SHA256, 'receipt toolchain pin mismatch')
    for key in ('run_id', 'run_attempt'):
        require(type(receipt[key]) is int and receipt[key] > 0, key + ': positive actual run identifier required')
    captured = datetime.datetime.fromisoformat(receipt['captured_at'].replace('Z', '+00:00'))
    require(captured.utcoffset() == datetime.timedelta(0), 'receipt UTC cutoff required')
    require(receipt['verdict'] == 'PASS' and receipt['gates'] == GATES, 'receipt missing complete build gates')
    require(all(receipt[key] is False for key in ('deployed', 'archive_invoked', 'd1_written')), 'build receipt cannot claim runtime proof')
    config = receipt['gated_oci_config_digest']
    require(isinstance(config, str) and DIGEST.fullmatch(config) is not None, 'gated OCI config digest invalid')
    images = receipt['images']
    require(isinstance(images, list) and len(images) == 5, 'five exact image receipts required')
    require([image.get('name') for image in images] == list(IMAGES), 'image repository inventory/order drift')
    tags = set()
    for image in images:
        require(set(image) == {'name', 'tag', 'digest', 'config_digest'}, 'closed image receipt schema drift')
        tag = image['tag']
        match = re.fullmatch(r'([0-9a-f]{7,40})-r1', tag)
        require(match is not None and SOURCE.startswith(match.group(1)), 'image tag must identify actual image source, not workflow candidate')
        require(DIGEST.fullmatch(image['digest']) is not None and image['config_digest'] == config, 'registry digest/config attribution mismatch')
        tags.add(tag)
        expected_ref = 'registry.cloudflare.com/' + ACCOUNT + '/' + image['name'] + ':' + tag
        lines = re.findall(r'^image = "(registry\.cloudflare\.com/[^\"]+/'+ re.escape(image['name']) + r':[^\"]+)"$', wrangler, re.MULTILINE)
        require(lines == [expected_ref], 'production pin missing, duplicate or mismatched: ' + image['name'])
    require(len(tags) == 1, 'production pins must share one actual build tag')


def verify_tree_attribution(root: Path, receipt: dict) -> None:
    for ancestor in (SOURCE, receipt['workflow_candidate_sha']):
        require(subprocess.run(['git', '-C', str(root), 'merge-base', '--is-ancestor', ancestor, 'HEAD'], capture_output=True).returncode == 0, 'receipt source/workflow candidate must be ancestors of final pin commit')
    native = ['crates/', 'Dockerfile', 'Cargo.toml', 'Cargo.lock']
    require(subprocess.run(['git', '-C', str(root), 'diff', '--quiet', SOURCE, 'HEAD', '--', *native], capture_output=True).returncode == 0, 'final candidate native image source differs from built source')
    workflow_controls = [str(WORKFLOW), 'scripts/verify_b063_hosted_build_workflow.py', 'scripts/test_verify_b063_hosted_build_workflow.py']
    require(subprocess.run(['git', '-C', str(root), 'diff', '--quiet', receipt['workflow_candidate_sha'], 'HEAD', '--', *workflow_controls], capture_output=True).returncode == 0, 'reviewed build workflow/guard changed after artifact')


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=ROOT)
    args = parser.parse_args()
    try:
        validate_workflow((args.root / WORKFLOW).read_text())
        receipt_path = args.root / RECEIPT
        if receipt_path.exists():
            receipt = json.loads(receipt_path.read_text())
            validate_receipt(receipt, (args.root / 'wrangler.toml').read_text())
            verify_tree_attribution(args.root, receipt)
            print('B-063 static workflow and build-source/pin attribution PASS; root must independently verify actual Actions/provider receipt')
        else:
            print('B-063 static build contract PASS; provider artifact/pins pending')
        return 0
    except (ContractError, KeyError, TypeError, ValueError, AttributeError, OSError, yaml.YAMLError) as error:
        print('B-063 FAIL_CLOSED: ' + str(error))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
