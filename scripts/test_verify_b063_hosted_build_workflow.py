"""Adversarial static controls. Synthetic receipts here are never build evidence."""
from copy import deepcopy
import hashlib
from pathlib import Path
import subprocess
import unittest

import yaml

from scripts import verify_b063_hosted_build_workflow as guard


class WorkflowControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = (guard.ROOT / guard.WORKFLOW).read_text()
        cls.document = yaml.load(cls.text, Loader=yaml.BaseLoader)

    def reject(self, change, reason):
        document = deepcopy(self.document)
        change(document)
        with self.assertRaisesRegex(guard.ContractError, reason):
            guard.validate_workflow(yaml.safe_dump(document, sort_keys=False))

    def test_valid_candidate_and_baseline_gate_bytes(self):
        guard.validate_workflow(self.text)
        baseline = subprocess.check_output(
            ['git', '-C', str(guard.ROOT), 'show', guard.SOURCE + ':' + str(guard.WORKFLOW)],
            text=True,
        )
        original = yaml.load(baseline, Loader=yaml.BaseLoader)['jobs']['build-push']
        commands = {step['name']: step['run'] for step in original['steps'] if 'run' in step}
        for name, digest in guard.SHARED_STEP_SHA256.items():
            with self.subTest(gate=name):
                self.assertEqual(hashlib.sha256(commands[name].encode()).hexdigest(), digest)

    def test_event_ref_and_exact_sha_guards(self):
        for name in self.document['jobs']:
            self.reject(lambda d: d['jobs'][name].__setitem__('if', 'true'), 'event/ref/SHA')
        self.reject(lambda d: d['on'].__setitem__('push', {}), 'manual-only')
        self.reject(lambda d: d['on']['workflow_dispatch']['inputs']['runner_route'].__setitem__('default', 'hosted-b063'), 'default')

    def test_no_execution_override_or_privilege_widening(self):
        self.reject(lambda d: d.__setitem__('defaults', {'run': {'shell': 'bash +e {0}'}}), 'modifiers')
        self.reject(lambda d: d['permissions'].__setitem__('contents', 'write'), 'permissions')
        self.reject(lambda d: d['jobs']['hosted-b063'].__setitem__('container', 'foreign/image'), 'modifier')
        self.reject(lambda d: d['jobs']['hosted-b063'].__setitem__('environment', 'production'), 'environment')
        self.reject(lambda d: d['jobs']['hosted-b063'].__setitem__('runs-on', 'ubuntu-latest'), 'runner')

    def test_source_and_credentials_bound_before_build(self):
        checkout = lambda d: next(s for s in d['jobs']['hosted-b063']['steps'] if s['name'] == 'Checkout')
        self.reject(lambda d: checkout(d)['with'].__setitem__('ref', '${{ github.sha }}'), 'source')
        self.reject(lambda d: checkout(d)['with'].__setitem__('persist-credentials', 'true'), 'source')
        self.reject(lambda d: d['jobs']['hosted-b063']['env'].__setitem__('CLOUDFLARE_ACCOUNT_ID', 'another-account'), 'binding')

    def test_gate_skips_and_failure_bypasses(self):
        for step_name in guard.SHARED_STEP_SHA256:
            with self.subTest(gate=step_name):
                step = lambda d: next(s for s in d['jobs']['hosted-b063']['steps'] if s['name'] == step_name)
                self.reject(lambda d: step(d).__setitem__('if', 'false'), 'metadata')
                self.reject(lambda d: step(d).__setitem__('continue-on-error', 'true'), 'bypass')
                self.reject(lambda d: step(d).__setitem__('run', 'echo PASS'), 'command hash')

    def test_command_and_secret_handling_negatives(self):
        mutations = [
            ('Bind reviewed workflow to frozen protected image source', guard.ACCOUNT, 'foreign-account'),
            ('Install canonical checksum-pinned BuildKit and runc', guard.BUNDLE_SHA256, '0' * 64),
            ('Push image to the 5 CF Containers registries (daemonless, wrangler cred)', 'chmod 0600', 'chmod 0644'),
            ('Push image to the 5 CF Containers registries (daemonless, wrangler cred)', 'umask 077', 'umask 022'),
            ('Push image to the 5 CF Containers registries (daemonless, wrangler cred)', 'select(type == \"string\" and length > 0)', '.'),
            ('Push image to the 5 CF Containers registries (daemonless, wrangler cred)', '::add-mask::$P', 'unmasked:$P'),
            ('Push image to the 5 CF Containers registries (daemonless, wrangler cred)', '"$RUNNER_TEMP/dockercfg"', '"$GITHUB_WORKSPACE/dockercfg"'),
            ('Push image to the 5 CF Containers registries (daemonless, wrangler cred)', 'CONFIG_DIGEST" ==', 'CONFIG_DIGEST" !='),
            ('Read-only exact production registry target preflight', 'if not expected <= actual:', 'if False:'),
        ]
        for name, old, new in mutations:
            with self.subTest(control=name, mutation=old):
                def mutate(d):
                    step = next(s for s in d['jobs']['hosted-b063']['steps'] if s['name'] == name)
                    self.assertIn(old, step['run'])
                    step['run'] = step['run'].replace(old, new, 1)
                self.reject(mutate, 'command hash')
        cleanup = lambda d: d['jobs']['hosted-b063']['steps'][-1]
        self.reject(lambda d: cleanup(d).__setitem__('if', 'success()'), 'metadata')
        upload = lambda d: d['jobs']['hosted-b063']['steps'][-2]
        self.reject(lambda d: upload(d)['with'].__setitem__('path', '${{ runner.temp }}/**'), 'allowlist')

    def test_contract_job_cannot_become_false_green_or_provider_job(self):
        self.reject(lambda d: d['jobs']['b063-contract'].__setitem__('env', {'TOKEN': '${{ secrets.CF_API_TOKEN }}'}), 'modifier')
        self.reject(lambda d: d['jobs']['b063-contract']['steps'][2].__setitem__('run', 'echo PASS'), 'command bypass')
        self.reject(lambda d: d['jobs']['b063-contract']['steps'][2].__setitem__('shell', 'bash +e {0}'), 'modifier')


class ReceiptControls(unittest.TestCase):
    def setUp(self):
        # Deliberately synthetic; kept in memory, never written to evidence/.
        self.receipt = {
            'schema_version': 1, 'captured_at': '2026-09-27T04:00:00Z', 'issue': 1648,
            'source_sha': guard.SOURCE, 'workflow_candidate_sha': 'a' * 40,
            'run_id': 1, 'run_attempt': 1, 'account_id': guard.ACCOUNT,
            'tool_bundle_version': '2.3.5', 'tool_bundle_sha256': guard.BUNDLE_SHA256,
            'gated_oci_config_digest': 'sha256:' + 'b' * 64,
            'images': [{'name': name, 'tag': guard.SOURCE[:7] + '-r1',
                        'digest': 'sha256:' + 'c' * 64, 'config_digest': 'sha256:' + 'b' * 64}
                       for name in guard.IMAGES],
            'gates': list(guard.GATES), 'verdict': 'PASS',
            'deployed': False, 'archive_invoked': False, 'd1_written': False,
        }
        self.pins = '\n'.join('image = "registry.cloudflare.com/' + guard.ACCOUNT + '/' + name + ':' + guard.SOURCE[:7] + '-r1"' for name in guard.IMAGES)

    def reject(self, change, reason, pins=None):
        receipt = deepcopy(self.receipt)
        change(receipt)
        with self.assertRaisesRegex(guard.ContractError, reason):
            guard.validate_receipt(receipt, self.pins if pins is None else pins)

    def test_complete_build_shape(self):
        guard.validate_receipt(self.receipt, self.pins)

    def test_receipt_attribution_and_runtime_claims(self):
        self.reject(lambda r: r.__setitem__('source_sha', 'a' * 40), 'frozen')
        self.reject(lambda r: r.__setitem__('workflow_candidate_sha', guard.SOURCE), 'distinct')
        self.reject(lambda r: r.__setitem__('account_id', 'foreign'), 'account')
        self.reject(lambda r: r.__setitem__('run_id', True), 'actual run')
        self.reject(lambda r: r.__setitem__('captured_at', '2026-09-27T04:00:00+01:00'), 'UTC')
        self.reject(lambda r: r['gates'].pop(), 'complete build gates')
        for field in ('deployed', 'archive_invoked', 'd1_written'):
            self.reject(lambda r: r.__setitem__(field, True), 'runtime')

    def test_image_inventory_and_immutable_digest(self):
        self.reject(lambda r: r['images'].pop(), 'five exact')
        self.reject(lambda r: r['images'][0].__setitem__('name', 'foreign-repository'), 'inventory')
        self.reject(lambda r: r['images'][0].__setitem__('tag', 'a' * 7 + '-r1'), 'actual image source')
        self.reject(lambda r: r['images'][0].__setitem__('digest', 'latest'), 'attribution')
        self.reject(lambda r: r['images'][0].__setitem__('config_digest', 'sha256:' + 'd' * 64), 'attribution')
        self.reject(lambda r: r.__setitem__('registry_password', 'synthetic'), 'closed receipt')

    def test_all_five_pins_match_build(self):
        self.reject(lambda r: None, 'pin missing', pins=self.pins.replace(guard.SOURCE[:7] + '-r1', '9308f4aa8-r1', 1))
        self.reject(lambda r: None, 'duplicate', pins=self.pins + '\n' + self.pins.splitlines()[0])
        self.reject(lambda r: None, 'pin missing', pins=self.pins.replace(guard.ACCOUNT, 'foreign-account', 1))


if __name__ == '__main__':
    unittest.main()
