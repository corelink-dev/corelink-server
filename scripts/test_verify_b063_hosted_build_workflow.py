"""Adversarial static controls. Synthetic receipts here are never build evidence."""
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

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
        current = {step['name']: step['run'] for step in self.document['jobs']['hosted-b063']['steps'] if 'run' in step}
        for name, digest in guard.SHARED_STEP_SHA256.items():
            with self.subTest(gate=name):
                expected = commands[name]
                for binary in ('gc_sweep', 'corelink-gc-sweep-production'):
                    old_probe = f'[ -x "$B/rootfs/usr/local/bin/{binary}" ] || {{'
                    new_probe = f"""  # The exported rootfs is root-owned; runc executes under the same sudo boundary.
  sudo stat -c 'rootfs executable probe: mode=%a uid=%u gid=%g path=%n' \\
    "$B/rootfs" "$B/rootfs/usr" "$B/rootfs/usr/local" "$B/rootfs/usr/local/bin" \\
    "$B/rootfs/usr/local/bin/{binary}"
  sudo test -x "$B/rootfs/usr/local/bin/{binary}" || {{"""
                    new_probe = "\n".join(line[2:] if line.startswith("  ") else line for line in new_probe.split("\n"))
                    expected = expected.replace(old_probe, new_probe)
                if name.startswith(('Gate 4 —', 'Gate 4b —')):
                    expected = expected.replace('runc spec -b "$B"\n',
                        '# Regenerate only the runner-owned spec left by the preceding smoke gate.\n'
                        'test -f "$B/config.json" && test ! -L "$B/config.json" && test -O "$B/config.json" || {\n'
                        "  echo '::error::GC spec is missing, a symlink, or not owned by the runner'\n"
                        '  exit 1\n}\n'
                        'rm -- "$B/config.json"\nrunc spec -b "$B"\n')
                # The exact baseline remainder includes every runc/GC oracle.
                self.assertEqual(current[name], expected)
                self.assertEqual(hashlib.sha256(expected.encode()).hexdigest(), digest)

    def test_gc_permission_boundary_cannot_be_weakened(self):
        for name, binary in (
            ('Gate 4 — embedded GC binary is forced dry-run (daemonless)', 'gc_sweep'),
            ('Gate 4b — native production GC binary is present and fail-closed', 'corelink-gc-sweep-production'),
        ):
            for replacement in ('test -x', 'sudo test -e', 'sudo test -f', 'echo'):
                with self.subTest(gate=name, probe=replacement):
                    def mutate(d):
                        step = next(s for s in d['jobs']['hosted-b063']['steps'] if s['name'] == name)
                        step['run'] = step['run'].replace('sudo test -x', replacement, 1)
                    self.reject(mutate, 'command hash')

    def test_gc_spec_regeneration_is_owned_and_exact(self):
        for name in ('Gate 4 — embedded GC binary is forced dry-run (daemonless)',
                     'Gate 4b — native production GC binary is present and fail-closed'):
            for old, new in (
                ('test ! -L "$B/config.json"', 'true'),
                ('test -O "$B/config.json"', 'true'),
                ('rm -- "$B/config.json"', 'rm -rf -- "$B/rootfs"'),
                ('rm -- "$B/config.json"', 'true'),
            ):
                with self.subTest(gate=name, mutation=old):
                    def mutate(d):
                        step = next(s for s in d['jobs']['hosted-b063']['steps'] if s['name'] == name)
                        step['run'] = step['run'].replace(old, new, 1)
                    self.reject(mutate, 'command hash')

    def test_actual_gc_spec_guard_refuses_missing_or_symlink_before_removal(self):
        for job in ('build-push', 'hosted-b063'):
            for gate in ('Gate 4 — embedded GC binary is forced dry-run (daemonless)',
                         'Gate 4b — native production GC binary is present and fail-closed'):
                command = next(s['run'] for s in self.document['jobs'][job]['steps'] if s['name'] == gate)
                code = command[command.index('test -f "$B/config.json"'):command.index('runc spec -b "$B"')]
                for kind in ('owned-regular', 'missing', 'symlink'):
                    with self.subTest(job=job, gate=gate, config=kind), tempfile.TemporaryDirectory(prefix='b063-owned-config-') as directory:
                        root = Path(directory)
                        retained = root / 'retained.json'
                        retained.write_text('{}')
                        config = root / 'config.json'
                        if kind == 'owned-regular':
                            config.write_text('{}')
                        elif kind == 'symlink':
                            config.symlink_to(retained)
                        result = subprocess.run(['bash', '-euo', 'pipefail', '-c', code],
                            env={**os.environ, 'B': directory}, capture_output=True, text=True)
                        self.assertEqual(result.returncode == 0, kind == 'owned-regular')
                        self.assertTrue(retained.is_file())
                        self.assertEqual(config.is_symlink(), kind == 'symlink')
                        if kind == 'owned-regular':
                            self.assertFalse(config.exists())

    def spec_fixture(self):
        step = next(s for s in self.document['jobs']['hosted-b063']['steps'] if s['name'] == 'Install canonical checksum-pinned BuildKit and runc')
        return step['run'].split('# B063_RUNC_SPEC_FIXTURE_BEGIN:', 1)[1].split('# B063_RUNC_SPEC_FIXTURE_END', 1)[0].split('\n', 1)[1]

    def test_spec_fixture_proves_regeneration_and_unsafe_path_negatives(self):
        fixture = self.spec_fixture()
        self.assertIn('regenerate_owned_spec\nregenerate_owned_spec\n', fixture)
        for marker in ('File config.json exists. Remove it first', 'test ! -L', 'test -O',
                       'foreign-owned spec', 'missing spec', 'symlink spec', 'retained-spec.json'):
            self.assertIn(marker, fixture)
        name = 'Install canonical checksum-pinned BuildKit and runc'
        def mutate(d):
            step = next(s for s in d['jobs']['hosted-b063']['steps'] if s['name'] == name)
            step['run'] = step['run'].replace('regenerate_owned_spec\nregenerate_owned_spec\n', 'true\ntrue\n')
        self.reject(mutate, 'command hash')

    def test_actual_spec_regeneration_fixture_on_hosted_linux(self):
        if sys.platform != 'linux' or os.geteuid() == 0:
            self.skipTest('requires the unprivileged hosted Linux runner with pinned runc')
        if subprocess.run(['sudo', '-n', 'true'], capture_output=True).returncode:
            self.skipTest('requires the hosted runner passwordless sudo boundary')
        # Credentialless contract job does not install the privileged runtime.
        if not __import__('shutil').which('runc'):
            self.skipTest('actual fixture runs before build after checksum-pinned runc installation')
        with tempfile.TemporaryDirectory(prefix='b063-spec-test-') as directory:
            result = subprocess.run(['bash', '-euo', 'pipefail', '-c', self.spec_fixture()],
                                    env={**os.environ, 'RUNNER_TEMP': directory}, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
            self.assertIn('existing refused; regenerated twice; foreign-owned/missing/symlink denied', result.stdout)
            self.assertEqual(list(Path(directory).iterdir()), [])

    def permission_fixture(self):
        step = next(s for s in self.document['jobs']['hosted-b063']['steps'] if s['name'] == 'Install canonical checksum-pinned BuildKit and runc')
        return step['run'].split('# B063_PERMISSION_FIXTURE_BEGIN:', 1)[1].split('# B063_PERMISSION_FIXTURE_END', 1)[0].split('\n', 1)[1]

    def test_permission_fixture_requires_positive_and_both_negatives(self):
        fixture = self.permission_fixture()
        for required in (
            'sudo install -d -o 0 -g 0 -m 0700',
            'sudo install -o 0 -g 0 -m 0755',
            'sudo install -o 0 -g 0 -m 0644',
            'if test -x "$fixture/rootfs/executable"; then',
            'sudo test -x "$fixture/rootfs/executable"',
            'sudo test -x "$fixture/rootfs/nonexecutable" || sudo test -x "$fixture/rootfs/missing"',
            "trap 'sudo rm -rf -- \"$fixture\"' EXIT",
        ):
            self.assertIn(required, fixture)
        name = 'Install canonical checksum-pinned BuildKit and runc'
        def mutate(d):
            step = next(s for s in d['jobs']['hosted-b063']['steps'] if s['name'] == name)
            step['run'] = step['run'].replace('sudo test -x "$fixture/rootfs/executable"', 'true', 1)
        self.reject(mutate, 'command hash')

    def test_actual_root_owned_permission_fixture_on_hosted_linux(self):
        # macOS has no passwordless sudo. The hosted build independently runs
        # this same fixture before compiling or minting registry credentials.
        if sys.platform != 'linux' or os.geteuid() == 0:
            self.skipTest('requires the unprivileged hosted Linux runner')
        if subprocess.run(['sudo', '-n', 'true'], capture_output=True).returncode:
            self.skipTest('requires the hosted runner passwordless sudo boundary')
        with tempfile.TemporaryDirectory(prefix='b063-permission-test-') as directory:
            result = subprocess.run(['bash', '-euo', 'pipefail', '-c', self.permission_fixture()],
                                    env={**os.environ, 'RUNNER_TEMP': directory}, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
            self.assertIn('host denied; executable accepted; missing/nonexec denied', result.stdout)
            self.assertEqual(list(Path(directory).iterdir()), [])

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
            ('Read-only exact production registry target preflight', "if not missing <= {'corelink-prod-syd-corelinkserver-prod'}:", 'if False:'),
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

    def run_inventory_preflight(self, inventory):
        step = next(s for s in self.document['jobs']['hosted-b063']['steps'] if s['name'] == 'Read-only exact production registry target preflight')
        code = step['run'].split("<<'PYTARGET'\n", 1)[1].rsplit('\nPYTARGET', 1)[0]
        # Execute only the inert Python inventory check, never the npx provider read.
        with tempfile.TemporaryDirectory(prefix='b063-inventory-test-') as directory:
            root = Path(directory)
            (root / 'b063-registry-inventory.json').write_text(json.dumps(inventory))
            with patch.dict(os.environ, {'RUNNER_TEMP': directory}):
                exec(compile(code, '<inert-b063-inventory>', 'exec'), {})
            return json.loads((root / 'b063-created-repo-expectation.json').read_text())

    def test_inventory_existing_all_or_exact_syd_creation_only(self):
        inventory = [{'name': name, 'tags': ['historical-test-tag']} for name in guard.IMAGES]
        self.assertEqual(self.run_inventory_preflight(inventory), [])
        self.assertEqual(self.run_inventory_preflight(inventory[:-1]), [guard.IMAGES[-1]])

    def test_inventory_denies_other_missing_duplicate_or_malformed(self):
        inventory = [{'name': name, 'tags': ['historical-test-tag']} for name in guard.IMAGES]
        bad_inventories = [
            inventory[1:], [], {}, inventory + [inventory[0]],
            [{'name': None, 'tags': []}], [{'name': guard.IMAGES[0], 'tags': None}],
            [dict(item, unexpected='field') for item in inventory],
        ]
        for bad in bad_inventories:
            with self.subTest(inventory=bad), self.assertRaises(SystemExit):
                self.run_inventory_preflight(bad)


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
            'created_repo_expectation': [guard.IMAGES[-1]],
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
        self.reject(lambda r: r.__setitem__('created_repo_expectation', [guard.IMAGES[0]]), 'unapproved')
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
