import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from harness.security import inventory
from harness.security_runtime import DockerSandbox, ISOLATION


class RuntimeTests(unittest.TestCase):
    def runner(self, root, ps_names='', image_missing=False):
        """A DockerSandbox whose .command is a recorder; the container-exec leg
        is patched separately in each test. Returns canned CLI output by argv."""
        runner = object.__new__(DockerSandbox)
        runner.control = Path(root).resolve()
        runner.calls = []

        def command(args, timeout=60, required=True, env=None):
            runner.calls.append(args)
            out, code = '', 0
            if args[:3] == ['docker', 'image', 'inspect']:
                out = 'sha256:builtimageid'
            elif args[:3] == ['docker', 'ps', '-a']:
                out = ps_names
            elif args[:3] == ['docker', 'image', 'rm'] and image_missing:
                out, code = 'Error: No such image', 1
            if required and code:
                raise RuntimeError(out)
            return subprocess.CompletedProcess(args, code, out, '')
        runner.command = command
        return runner

    def source_dir(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        (root / 'source').mkdir()
        (root / 'source' / 'target.py').write_text('VALUE = 1\n')
        return root

    def test_run_applies_isolation_flags(self):
        root = self.source_dir()
        source = root / 'source'
        runner = self.runner(root)
        done = subprocess.CompletedProcess([], 0, '{"outcome":"NOT_REPRODUCED"}', '')
        with patch('harness.security_runtime.subprocess.run', return_value=done):
            receipt = runner.run(source, 'print(1)', 'sha256:' + 'a' * 64,
                                 'ahs-sec-' + 'a' * 16, inventory(source))
        self.assertEqual(receipt['backend'], 'docker')
        self.assertEqual(receipt['exit_code'], 0)
        self.assertEqual(receipt['stdout'], '{"outcome":"NOT_REPRODUCED"}')
        self.assertEqual(receipt['capture_exit_codes'], [0])
        for flag in ('--network', 'none', '--read-only', '--cap-drop', 'ALL',
                     '--security-opt', 'no-new-privileges', '--user', '1000:1000',
                     '--pids-limit', '--memory'):
            self.assertIn(flag, receipt['run_command'])
        self.assertEqual(receipt['isolation'], ISOLATION)
        self.assertEqual(receipt['run_command'][-3:], ['ahs-sec-' + 'a' * 16 + ':test', 'python3', '/test.py'])

    def test_changed_source_prevents_build(self):
        root = self.source_dir()
        runner = self.runner(root)
        with patch('harness.security_runtime.subprocess.run') as run:
            with self.assertRaisesRegex(RuntimeError, 'admitted inventory'):
                runner.run(root / 'source', 'print(1)', 'sha256:' + 'a' * 64, 'ahs-sec-' + 'a' * 16, [])
            run.assert_not_called()
        self.assertEqual(runner.calls, [])

    def test_timeout_kills_container_and_records_124(self):
        root = self.source_dir()
        source = root / 'source'
        runner = self.runner(root)
        timeout = subprocess.TimeoutExpired(['docker', 'run'], 105, output='partial', stderr='')
        with patch('harness.security_runtime.subprocess.run', side_effect=timeout):
            receipt = runner.run(source, 'print(1)', 'sha256:' + 'a' * 64,
                                 'ahs-sec-' + 'b' * 16, inventory(source))
        self.assertEqual(receipt['exit_code'], 124)
        self.assertTrue(receipt['timed_out'])
        self.assertEqual(receipt['stdout'], 'partial')
        self.assertTrue(any(c[:2] == ['docker', 'kill'] for c in runner.calls))

    def test_stop_validates_name(self):
        runner = self.runner(self.source_dir())
        with self.assertRaises(ValueError):
            runner.stop('not-a-managed-name')

    def test_stop_removes_container_image_and_build(self):
        root = self.source_dir()
        name = 'ahs-sec-' + 'c' * 16
        build = root / 'build' / name
        build.mkdir(parents=True)
        runner = self.runner(root, ps_names='')
        runner.stop(name)
        self.assertFalse(build.exists())
        self.assertTrue(any(c[:3] == ['docker', 'rm', '-f'] for c in runner.calls))
        self.assertTrue(any(c[:3] == ['docker', 'image', 'rm'] for c in runner.calls))

    def test_stop_missing_image_is_tolerated(self):
        root = self.source_dir()
        name = 'ahs-sec-' + 'd' * 16
        runner = self.runner(root, image_missing=True)
        runner.stop(name)  # 'no such image' must not raise

    def test_stop_detects_container_still_listed(self):
        name = 'ahs-sec-' + 'e' * 16
        runner = self.runner(self.source_dir(), ps_names=name + '\n')
        with self.assertRaisesRegex(RuntimeError, 'still listed'):
            runner.stop(name)

    def test_command_capture_is_loss_tolerant(self):
        runner = object.__new__(DockerSandbox)
        with patch('harness.security_runtime.subprocess.run',
                   return_value=subprocess.CompletedProcess([], 0, '', '')) as run:
            DockerSandbox.command(runner, ['docker', 'version'])
        self.assertEqual(run.call_args.kwargs['errors'], 'replace')


if __name__ == '__main__':
    unittest.main()
