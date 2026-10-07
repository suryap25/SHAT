"""Offline Docker execution adapter. No target code executes on the host.

Each attempt bakes the admitted source snapshot and the operator-authored test
into a throwaway image, then runs it in a container with no network, a read-only
root filesystem, a non-root user, dropped capabilities and memory/CPU/pid caps.
The exact isolation argv is recorded in the receipt as evidence of what ran.
"""
import os
from pathlib import Path
import re
import shutil
import subprocess

from harness.artifacts import sha
from harness.security import inventory

# Hard isolation applied to every attempt. Recorded verbatim in the receipt.
ISOLATION = ['--network', 'none', '--read-only',
             '--tmpfs', '/workspace:rw,size=64m,mode=1777', '--tmpfs', '/tmp:rw,size=64m',
             '--memory', '512m', '--memory-swap', '512m', '--cpus', '1', '--pids-limit', '128',
             '--user', '1000:1000', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges']
WALL_SECONDS = 90
OUTPUT_LIMIT = 1048576
NAME = re.compile(r'ahs-sec-[0-9a-f]{16}')


class DockerSandbox:
    def __init__(self, control):
        if os.name != 'posix':
            raise RuntimeError('execution requires the qualified Linux Docker runtime')
        self.control = Path(control).resolve()
        if self.control == Path('/mnt') or Path('/mnt') in self.control.parents:
            raise RuntimeError('CONTROL must use Linux storage, not /mnt/*')

    def command(self, args, timeout=60, required=True, env=None):
        result = subprocess.run(args, capture_output=True, text=True, encoding='utf-8',
                                errors='replace', timeout=timeout, env=env)
        if required and result.returncode:
            raise RuntimeError((result.stderr + result.stdout)[-3000:])
        return result

    def ready(self):
        self.command(['docker', 'version', '--format', '{{.Server.Version}}'])

    def stop(self, sandbox):
        if not NAME.fullmatch(sandbox):
            raise ValueError('invalid managed sandbox name')
        # Force-remove the container, then its image, then the build context.
        self.command(['docker', 'rm', '-f', sandbox], required=False)
        if sandbox in self.command(['docker', 'ps', '-a', '--format', '{{.Names}}']).stdout.split():
            raise RuntimeError('container still listed after removal')
        image = self.command(['docker', 'image', 'rm', sandbox + ':test'], required=False)
        if image.returncode and 'no such image' not in (image.stderr + image.stdout).lower():
            raise RuntimeError('could not remove attempt image: ' + image.stderr[-1500:])
        base = (self.control / 'build').resolve()
        build = base / sandbox
        if build.is_symlink() or build.resolve().parent != base:
            raise RuntimeError('unsafe build cleanup path')
        if build.exists():
            shutil.rmtree(build)

    def run(self, source, script, image, sandbox, admitted_files):
        if not NAME.fullmatch(sandbox):
            raise ValueError('invalid managed sandbox name')
        build = self.control / 'build' / sandbox
        before = inventory(source)
        if before != admitted_files:
            raise RuntimeError('source differs from admitted inventory')
        build.mkdir(parents=True)
        shutil.copytree(source, build / 'source', symlinks=True)
        if inventory(build / 'source') != before or inventory(source) != before:
            raise RuntimeError('source changed while preparing build context')
        (build / 'test.py').write_text(script, encoding='utf-8')
        (build / 'Dockerfile').write_text(
            'FROM ' + image + '\nUSER root\nCOPY source /source\nCOPY test.py /test.py\n'
            'RUN mkdir -p /workspace && chmod 1777 /workspace && chmod -R a+rX /source /test.py\n'
            'ENV PYTHONPATH=/source/src PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1\n'
            'USER 1000:1000\nWORKDIR /workspace\nENTRYPOINT []\n')
        # ponytail: DOCKER_BUILDKIT=0 so `FROM sha256:<local-id>` resolves the
        # pinned base image by id. BuildKit treats a bare digest as a registry
        # repo and tries to pull it. Legacy builder is deprecated; if it is
        # dropped, tag the base locally and verify its id equals `image` instead.
        build_env = dict(os.environ, DOCKER_BUILDKIT='0')
        built = self.command(['docker', 'build', '--network=none', '-t', sandbox + ':test', str(build)],
                             timeout=180, env=build_env)
        actual_image = self.command(['docker', 'image', 'inspect', sandbox + ':test', '--format', '{{.Id}}']).stdout.strip()
        run_cmd = ['docker', 'run', '--name', sandbox] + ISOLATION + [sandbox + ':test', 'python3', '/test.py']
        timed_out = False
        try:
            execution = subprocess.run(run_cmd, capture_output=True, text=True, encoding='utf-8',
                                       errors='replace', timeout=WALL_SECONDS + 15)
            code, out, err = execution.returncode, execution.stdout, execution.stderr
        except subprocess.TimeoutExpired as exc:
            # The host wall timeout fired; kill the container so stop() finds nothing running.
            self.command(['docker', 'kill', sandbox], required=False)
            timed_out, code = True, 124
            out = (exc.stdout or '')
            err = (exc.stderr or '') + '\nhost wall timeout; container killed'
        # ponytail: subprocess buffers all child stdout in host memory before we can
        # truncate; a canary must confirm the guest cannot emit more than a container
        # memory cap allows. Receipt output is truncated to OUTPUT_LIMIT.
        return {'backend': 'docker', 'sandbox': sandbox, 'base_image': image, 'image': actual_image,
                'run_command': run_cmd, 'isolation': ISOLATION, 'exit_code': code, 'timed_out': timed_out,
                'stdout': out[:OUTPUT_LIMIT], 'stderr': err[:OUTPUT_LIMIT],
                'stdout_truncated': len(out) > OUTPUT_LIMIT, 'capture_exit_codes': [0],
                'build_log': (built.stdout + built.stderr)[-10000:]}
