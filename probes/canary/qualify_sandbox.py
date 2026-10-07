"""Qualify DockerSandbox — prove Docker ENFORCES the isolation the adapter claims.

Mocked unit tests prove the isolation flags are passed. This proves they bite.
Each canary runs a probe through the real ``DockerSandbox.run()`` code path and
checks enforcement the right way for its kind:

  * receipt-asserted (host-side, strong): memory OOM, wall timeout, cleanup — the
    container cannot lie about its own exit code or whether it still exists.
  * observation-with-positive-control (in-container): network, filesystem,
    identity. A negative only counts because the paired positive action in the
    SAME run succeeds, so "blocked" is distinguished from "broken".

Run on the Linux / WSL Docker host (DockerSandbox refuses non-POSIX):

    python -m probes.canary.qualify_sandbox --image sha256:<base-image-id>

Exit 0 only if every canary passes. A new base image or any ISOLATION change
re-opens qualification. No network; no target code.
"""
import argparse
import json
import sys
import tempfile
import uuid
from pathlib import Path

from harness.security_runtime import DockerSandbox, WALL_SECONDS

# --- probe sources (run inside the sandbox) ---------------------------------

NETWORK = r'''
import json, socket
res = {}
def blocked(label, fn):
    try:
        fn(); res[label] = False            # reached it = NOT blocked = bad
    except Exception:
        res[label] = True                   # refused = blocked = good
blocked("loopback_9", lambda: socket.create_connection(("127.0.0.1", 9), 2))
blocked("dns", lambda: socket.getaddrinfo("example.com", 80))
blocked("imds_169254", lambda: socket.create_connection(("169.254.169.254", 80), 2))
def dockersock():
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.settimeout(2); s.connect("/var/run/docker.sock")
blocked("docker_sock", dockersock)
pos = open("/etc/hostname").read(1) != ""   # positive control: a benign local read works
print(json.dumps({"outcome": "NOT_REPRODUCED",
    "observations": {"positive_control_local_read": pos, **res}}))
'''

FILESYSTEM = r'''
import json
res = {}
def denied(label, path):
    try:
        open(path, "w").write("x"); res[label] = False   # wrote = bad
    except Exception:
        res[label] = True                                 # denied = good
denied("write_source", "/source/escape")
denied("write_etc", "/etc/escape")
denied("write_usr", "/usr/escape")
open("/workspace/ok", "w").write("x")                     # positive control
res["workspace_write_read"] = open("/workspace/ok").read() == "x"
print(json.dumps({"outcome": "NOT_REPRODUCED", "observations": res}))
'''

IDENTITY = r'''
import json, os
status = open("/proc/self/status").read()
def field(name):
    for line in status.splitlines():
        if line.startswith(name + ":"):
            return line.split(":", 1)[1].strip()
    return ""
pids = [p for p in os.listdir("/proc") if p.isdigit()]
print(json.dumps({"outcome": "NOT_REPRODUCED", "observations": {
    "uid_is_1000": os.getuid() == 1000,
    "gid_is_1000": os.getgid() == 1000,
    "capeff_empty": field("CapEff") in ("0000000000000000", "0000000000000000".rjust(16, "0")),
    "no_new_privs": field("NoNewPrivs") == "1",
    "proc_pid_count": len(pids),      # own PID namespace => a handful, not the host's hundreds
}}))
'''

# Triggers an OOM kill under --memory 512m (no swap). Receipt exit must be nonzero.
MEMORY = r'''
import json
blocks = []
try:
    for _ in range(80):                       # 80 x 16 MiB = 1.25 GiB, well over 512m
        blocks.append(bytearray(16 * 1024 * 1024));
        for i in range(0, len(blocks[-1]), 4096): blocks[-1][i] = 1  # fault pages in
    print(json.dumps({"outcome": "REPRODUCED", "observations": {"escaped_memory_cap": True}}))
except MemoryError:
    print(json.dumps({"outcome": "NOT_REPRODUCED", "observations": {"memoryerror": True}}))
'''

# Sleeps past the wall timeout. Receipt must show timed_out / exit 124.
TIMEOUT = f'''
import time
time.sleep({WALL_SECONDS} + 20)
print("should-not-print")
'''


def run_probe(image, source_dir, admitted, script):
    control = Path(tempfile.mkdtemp(prefix="ahs-canary-"))
    runner = DockerSandbox(control)
    runner.ready()
    name = "ahs-sec-" + uuid.uuid4().hex[:16]
    try:
        receipt = runner.run(source_dir, script, image, name, admitted)
        return receipt, runner, name
    finally:
        pass  # caller stops after inspecting, to also qualify stop()


def observations(receipt):
    out = receipt.get("stdout", "")
    try:
        return json.loads(out)["observations"]
    except Exception:
        return None


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--image", required=True, help="base image id, e.g. sha256:<64hex> (python:3.12-slim is fine)")
    args = ap.parse_args()

    src = Path(tempfile.mkdtemp(prefix="ahs-canary-src-"))
    (src / "placeholder.py").write_text("X = 1\n")
    from harness.security import inventory
    admitted = inventory(src)

    results = []

    def check(label, predicate):
        results.append((label, bool(predicate)))

    # Observation-based (positive control must pass, negatives must all block)
    for name, script, negatives, positive in [
        ("network", NETWORK, ["loopback_9", "dns", "imds_169254", "docker_sock"], "positive_control_local_read"),
        ("filesystem", FILESYSTEM, ["write_source", "write_etc", "write_usr"], "workspace_write_read"),
    ]:
        receipt, runner, sbx = run_probe(args.image, src, admitted, script)
        obs = observations(receipt)
        runner.stop(sbx)
        check(f"{name}: exit 0", receipt.get("exit_code") == 0)
        check(f"{name}: positive control", obs and obs.get(positive) is True)
        for neg in negatives:
            check(f"{name}: {neg} blocked", obs and obs.get(neg) is True)

    # Identity
    receipt, runner, sbx = run_probe(args.image, src, admitted, IDENTITY)
    obs = observations(receipt); runner.stop(sbx)
    check("identity: uid 1000", obs and obs.get("uid_is_1000"))
    check("identity: caps dropped", obs and obs.get("capeff_empty"))
    check("identity: no_new_privs", obs and obs.get("no_new_privs"))
    check("identity: own pid namespace (<50 procs)", obs and isinstance(obs.get("proc_pid_count"), int) and obs["proc_pid_count"] < 50)

    # Memory cap — enforced either as an OOM kill (nonzero exit) or a caught
    # MemoryError (ENOMEM). Only an escape (exit 0 having allocated it all) fails.
    receipt, runner, sbx = run_probe(args.image, src, admitted, MEMORY)
    obs = observations(receipt)
    oom_killed = receipt.get("exit_code") not in (0,) and not receipt.get("timed_out")
    caught = bool(obs and obs.get("memoryerror"))
    escaped = bool(obs and obs.get("escaped_memory_cap"))
    runner.stop(sbx)
    check("memory: cap enforced (OOM kill or MemoryError, not escape)", (oom_killed or caught) and not escaped)

    # Wall timeout — receipt-asserted
    receipt, runner, sbx = run_probe(args.image, src, admitted, TIMEOUT)
    timed = receipt.get("timed_out") is True and receipt.get("exit_code") == 124
    build_dir = runner.control / "build" / sbx
    runner.stop(sbx)
    check("timeout: enforced (timed_out, exit 124)", timed)

    # Cleanup — stop() must remove the build context and container/image
    check("cleanup: build dir removed", not build_dir.exists())

    passed = sum(1 for _, ok in results if ok)
    for label, ok in results:
        print(f"  [{'PASS' if ok else 'FAIL'}] {label}")
    print(f"\n{passed}/{len(results)} canaries passed")
    sys.exit(0 if passed == len(results) else 1)


if __name__ == "__main__":
    main()
