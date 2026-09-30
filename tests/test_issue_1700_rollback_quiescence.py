import json
from pathlib import Path
import unittest
from scripts.issue_1700_rollback_quiescence import inspect


class QuiescenceTests(unittest.TestCase):
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
        rollback = workflow.split('      - name: Roll back only this run after runtime acceptance failure', 1)[1]
        self.assertLess(rollback.index('python3 scripts/issue_1700_rollback_quiescence.py'), rollback.index('pnpm exec wrangler deploy ' + chr(92)))
        self.assertEqual(rollback.count('python3 scripts/issue_1700_rollback_quiescence.py'), 2)
        self.assertIn('ROLLBACK_CONTAINER_RESTORE_ATTEMPTED=1 python3 scripts/issue_1700_rollback_quiescence.py\n          pnpm exec wrangler versions deploy', rollback)
        self.assertIn('staging-rollback-quiescence.json', rollback)
