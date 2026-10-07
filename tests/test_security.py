import json
import subprocess
import sys
from pathlib import Path
import tempfile
import unittest

from harness.security import Engagement
from harness.artifacts import canonical, sha


class FakeRunner:
    def __init__(self, outcome='REPRODUCED', bad=False):
        self.outcome, self.bad = outcome, bad
        self.calls = []
        self.stopped = []

    def run(self, source, script, image, sandbox, admitted_files):
        self.calls.append(sandbox)
        return {'exit_code': 0, 'stdout': 'bad' if self.bad else json.dumps(
            {'outcome': self.outcome, 'observations': {'synthetic': True}}), 'stderr': ''}

    def stop(self, sandbox):
        self.stopped.append(sandbox)


class SecurityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.target = self.base / 'target'
        self.target.mkdir()
        (self.target / 'target.py').write_text('VALUE = 1\n')
        self.script = self.base / 'test.py'
        self.script.write_text('print("test")\n')
        self.root = self.base / 'control'
        self.work = Engagement(self.root)
        self.addCleanup(lambda: self.work.close())
        self.work.admit(self.target, 'Test', 'synthetic authorized fixture', 'sha256:' + 'a'*64)
        self.work.recon({'author': 'synthetic fixture', 'entry_points': ['fixture'], 'trust_boundaries': ['fixture'],
                         'assumptions': ['synthetic'], 'paths': ['target.py']})
        self.work.add({'id': 'check', 'title': 'boundary', 'attacker': 'fixture caller',
                       'boundary': 'fixture', 'expected': 'deny', 'paths': ['target.py']}, self.script)

    def test_fresh_repeat_and_reopen(self):
        runner = FakeRunner()
        self.assertEqual(self.work.run(runner, 'check'), 'HUNT_DONE')
        self.work.close()
        self.work = Engagement(self.root)
        self.assertEqual(self.work.run(runner, 'check'), 'REVIEW_PENDING')
        self.assertNotEqual(*runner.calls)
        self.assertEqual(runner.stopped, runner.calls)
        with self.assertRaises(ValueError):
            self.work.run(runner, 'check')
        report = self.work.export(self.base / 'review')
        self.assertEqual(len(report['package_digest']), 64)

    def test_malformed_success_is_tool_failure(self):
        self.assertEqual(self.work.run(FakeRunner(bad=True), 'check'), 'TOOL_FAILED')
        self.assertIsNone(self.work.task('check')['hunt'])
        self.assertIn('error', self.work.package()['attempts'][0]['evidence'])

    def test_disagreement_not_confirmation(self):
        self.work.run(FakeRunner(), 'check')
        self.assertEqual(self.work.run(FakeRunner('NOT_REPRODUCED'), 'check'), 'INCONCLUSIVE')

    def test_provider_block_and_explicit_resume(self):
        self.work.block('check', 'PROVIDER_BLOCKED', 'Synthetic provider refusal fixture')
        with self.assertRaises(ValueError):
            self.work.run(FakeRunner(), 'check')
        self.work.close()
        self.work = Engagement(self.root)
        self.assertEqual(self.work.task('check')['state'], 'PROVIDER_BLOCKED')
        self.work.resume('check', 'Operator supplies authorized local test')
        self.assertEqual(self.work.task('check')['state'], 'READY')

    def test_interrupted_execution_is_never_success(self):
        class Crash(FakeRunner):
            def run(self, *args):
                raise KeyboardInterrupt()
        with self.assertRaises(KeyboardInterrupt):
            self.work.run(Crash(), 'check')
        self.work.close()
        self.work = Engagement(self.root)
        runner = FakeRunner()
        self.work.recover(runner)
        self.assertEqual(self.work.task('check')['state'], 'INTERRUPTED')
        self.assertEqual(len(runner.stopped), 1)
        self.assertEqual(runner.calls, [])

    def test_changed_snapshot_blocks_execution(self):
        (self.root / 'source' / 'target.py').write_text('changed')
        with self.assertRaises(ValueError):
            self.work.run(FakeRunner(), 'check')

    def test_corrupt_evidence_blocks_export(self):
        self.work.run(FakeRunner(), 'check')
        with self.work.db:
            self.work.db.execute("UPDATE artifacts SET body='{}'")
        with self.assertRaises(ValueError):
            self.work.export(self.base / 'review')

    def test_missing_source_rejected(self):
        with self.assertRaises(ValueError):
            self.work.add({'id': 'other', 'title': 'x', 'attacker': 'x', 'boundary': 'x',
                           'expected': 'x', 'paths': ['missing.py']}, self.script)

    def response(self):
        return {'package_digest': sha(canonical(self.work.package())), 'reviewer': 'synthetic test reviewer',
                'kind': 'INDEPENDENT_REVIEW', 'tasks': [{'id': 'check', 'decision': 'CONFIRM',
                'reason': 'Synthetic review fixture only'}], 'limitations': ['Not a real human decision']}

    def test_confirmation_requires_two_reproductions(self):
        with self.assertRaises(ValueError):
            self.work.review(self.response())
        self.work.run(FakeRunner(), 'check')
        with self.assertRaises(ValueError):
            self.work.review(self.response())
        self.work.run(FakeRunner(), 'check')
        reply = self.response()
        self.work.review(reply)
        self.assertEqual(self.work.decide(reply['package_digest'], 'ACCEPT', 'test fixture')['decision'], 'ACCEPT')

    def test_stale_review_rejected(self):
        reply = self.response()
        self.work.run(FakeRunner(), 'check')
        with self.assertRaises(ValueError):
            self.work.review(reply)

    def test_no_reproduction_cannot_be_confirmed(self):
        self.work.run(FakeRunner('NOT_REPRODUCED'), 'check')
        self.work.run(FakeRunner('NOT_REPRODUCED'), 'check')
        with self.assertRaises(ValueError):
            self.work.review(self.response())

    def test_controller_lock(self):
        with self.assertRaises(OSError):
            Engagement(self.root)

    def test_receipt_survives_cleanup_failure_without_rerun(self):
        class CleanupFailure(FakeRunner):
            def stop(self, sandbox):
                raise RuntimeError('synthetic cleanup failure')
        with self.assertRaises(RuntimeError):
            self.work.run(CleanupFailure(), 'check')
        self.work.close()
        self.work = Engagement(self.root)
        runner = FakeRunner()
        self.work.recover(runner)
        self.assertEqual(self.work.task('check')['state'], 'HUNT_DONE')
        self.assertEqual(runner.calls, [])

    def test_timeout_retains_failed_receipt(self):
        class Timeout(FakeRunner):
            def run(self, *args):
                return {'exit_code': 124, 'stdout': '', 'stderr': 'synthetic timeout'}
        self.assertEqual(self.work.run(Timeout(), 'check'), 'TOOL_FAILED')
        self.assertEqual(self.work.package()['attempts'][0]['evidence']['exit_code'], 124)

    def test_actual_process_exit_releases_lock_and_preserves_attempt(self):
        self.work.close()
        code = '''import os,sys
from harness.security import Engagement
class Crash:
    def run(self,*args): os._exit(137)
with Engagement(sys.argv[1]) as e: e.run(Crash(),'check')
'''
        result = subprocess.run([sys.executable, '-c', code, str(self.root)], timeout=15)
        self.work = Engagement(self.root)
        self.assertEqual(result.returncode, 137)
        self.assertEqual(self.work.task('check')['state'], 'RUNNING')
        self.work.recover(FakeRunner())
        self.assertEqual(self.work.task('check')['state'], 'INTERRUPTED')

    def test_active_execution_blocks_package_review_and_disposition(self):
        reply = self.response()
        class Crash(FakeRunner):
            def run(self, *args):
                raise KeyboardInterrupt()
        with self.assertRaises(KeyboardInterrupt):
            self.work.run(Crash(), 'check')
        for action in (self.work.package, lambda: self.work.export(self.base / 'active'),
                       lambda: self.work.review(reply),
                       lambda: self.work.decide(reply['package_digest'], 'ACCEPT', 'fixture')):
            with self.assertRaisesRegex(ValueError, 'active execution'):
                action()
        self.work.recover(FakeRunner())
        self.work.resume('check', 'explicit recovery')
        self.assertEqual(self.work.run(FakeRunner(), 'check'), 'HUNT_DONE')

    def test_unresolved_acceptance_and_report(self):
        self.work.block('check', 'PROVIDER_BLOCKED', 'fixture refusal')
        reply = self.response()
        reply['tasks'][0]['decision'] = 'NEEDS_EVIDENCE'
        self.work.review(reply)
        with self.assertRaisesRegex(ValueError, 'acknowledge-unresolved'):
            self.work.decide(reply['package_digest'], 'ACCEPT', 'fixture')
        self.work.decide(reply['package_digest'], 'ACCEPT', 'fixture', True)
        self.work.decide(reply['package_digest'], 'ACCEPT', 'fixture', True)
        self.work.export(self.base / 'review')
        self.assertIn('NEEDS_EVIDENCE', (self.base / 'review/REPORT.md').read_text())
        disposition = json.loads((self.base / 'review/disposition.json').read_text())
        self.assertEqual(json.loads(disposition['summary'])['unresolved'], ['check'])

    def test_rejected_completed_test_is_resolved_not_confirmed(self):
        self.work.run(FakeRunner('NOT_REPRODUCED'), 'check')
        self.work.run(FakeRunner('NOT_REPRODUCED'), 'check')
        reply = self.response()
        reply['tasks'][0]['decision'] = 'REJECT'
        self.work.review(reply)
        self.work.decide(reply['package_digest'], 'ACCEPT', 'fixture')

    def test_rejected_positive_requires_acknowledgment(self):
        self.work.run(FakeRunner(), 'check')
        self.work.run(FakeRunner(), 'check')
        reply = self.response()
        reply['tasks'][0]['decision'] = 'REJECT'
        self.work.review(reply)
        with self.assertRaisesRegex(ValueError, 'acknowledge-unresolved'):
            self.work.decide(reply['package_digest'], 'ACCEPT', 'fixture')
        self.work.decide(reply['package_digest'], 'ACCEPT', 'fixture', True)

    def test_malformed_review_types(self):
        for field, value in [('reviewer', []), ('tasks', [None]), ('tasks', [{'id': []}])]:
            reply = self.response()
            reply[field] = value
            with self.assertRaises(ValueError):
                self.work.review(reply)

    def test_validate_cleanup_recovery_and_changed_snapshot(self):
        self.work.run(FakeRunner(), 'check')
        class CleanupFailure(FakeRunner):
            def stop(self, sandbox):
                raise RuntimeError('cleanup failed')
        with self.assertRaises(RuntimeError):
            self.work.run(CleanupFailure(), 'check')
        path = self.root / 'source/target.py'
        original = path.read_bytes()
        path.write_text('changed')
        with self.assertRaises(ValueError):
            self.work.recover(FakeRunner())
        path.write_bytes(original)
        self.work.recover(FakeRunner())
        self.assertEqual(self.work.task('check')['state'], 'REVIEW_PENDING')

    def test_cancel_prevents_execution(self):
        self.work.cancel('check', 'operator stops this investigation')
        with self.assertRaises(ValueError):
            self.work.run(FakeRunner(), 'check')


if __name__ == '__main__':
    unittest.main()
