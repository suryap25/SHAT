"""AHS environment preflight — GO / NO-GO per prerequisite for THIS machine.

Run before using the harness on a new laptop (macOS, Linux, or Windows+WSL):

    python3 -m harness.doctor                              # fast environment preflight
    python3 -m harness.doctor --qualify python:3.12-slim   # also run the sandbox canaries

Exit 0 only if every hard requirement passes. stdlib only; it reports, it never
installs anything. The image-builder check pulls a tiny image (busybox) if absent.
"""
import argparse
import os
import platform
import shutil
import subprocess
import sys
import tempfile

GO, WARN, NOGO = "GO", "WARN", "NO-GO"


def _docker(args, timeout=60, env=None):
    return subprocess.run(["docker", *args], capture_output=True, text=True, timeout=timeout, env=env)


def check_python():
    v = sys.version_info
    ok = (v.major, v.minor) >= (3, 12)
    return (GO if ok else NOGO, f"Python {v.major}.{v.minor}.{v.micro} (need >= 3.12)")


def check_os():
    if os.name == "posix":
        return (GO, f"{platform.system()} (posix) — harness runs natively, no WSL layer")
    return (NOGO, f"{platform.system()} — harness needs a POSIX host; on Windows run it inside WSL")


def check_docker_cli():
    path = shutil.which("docker")
    return (GO, path) if path else (NOGO, "`docker` not on PATH — install Docker Desktop / engine")


def check_docker_daemon():
    try:
        r = _docker(["version", "--format", "{{.Server.Version}}"])
    except Exception as e:  # noqa: BLE001 - any failure here is the same "daemon not reachable"
        return (NOGO, f"docker not runnable: {e}")
    if r.returncode != 0:
        return (NOGO, "daemon not reachable — start Docker Desktop / the engine")
    return (GO, f"daemon {r.stdout.strip()}")


def check_arch():
    try:
        r = _docker(["version", "--format", "{{.Server.Arch}}"])
        arch = r.stdout.strip() if r.returncode == 0 else platform.machine()
    except Exception:  # noqa: BLE001
        arch = platform.machine()
    hint = "use arm64 / multi-arch images" if arch in ("arm64", "aarch64") else "use amd64 images"
    return (GO, f"{arch} — {hint} for base/probe images")


def check_legacy_builder():
    """The sandbox builds with DOCKER_BUILDKIT=0 so `FROM sha256:<id>` resolves a
    LOCAL pinned image. Docker Desktop may ship BuildKit-only, where that fails —
    detect it here so a machine finds out now, not mid-engagement. Tested against
    a local image id (no network pull), using the exact FROM form the harness uses."""
    try:
        ids = _docker(["images", "--no-trunc", "-q"]).stdout.split()
        local = next((i for i in ids if i.startswith("sha256:")), None)
        if local is None:
            return (WARN, "no local image to test the builder offline — rerun after `docker pull "
                          "python:3.12-slim`, or let --qualify verify FROM sha256:<id>")
        env = dict(os.environ, DOCKER_BUILDKIT="0")
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "Dockerfile"), "w") as f:
                f.write(f"FROM {local}\nLABEL ahs=doctor\n")  # LABEL: no shell/pull needed
            r = _docker(["build", "-q", "-t", "ahs-doctor-probe", d], timeout=120, env=env)
        _docker(["image", "rm", "-f", "ahs-doctor-probe"], timeout=60)
        if r.returncode == 0:
            return (GO, "legacy builder resolves FROM sha256:<local-id> (DOCKER_BUILDKIT=0)")
        blob = (r.stderr + r.stdout).lower()
        if "buildkit" in blob and any(w in blob for w in ("require", "only", "must")) or "unknown" in blob:
            return (NOGO, "legacy builder unavailable — the sandbox's FROM sha256:<id> will fail; "
                          "implement the tag-based FROM fallback before running")
        return (WARN, "builder trial failed (may be network/transient): " + (r.stderr or r.stdout).strip()[-200:])
    except Exception as e:  # noqa: BLE001
        return (WARN, f"could not test the image builder: {e}")


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--qualify", metavar="IMAGE",
                    help="after preflight, run probes.canary.qualify_sandbox against this base image")
    args = ap.parse_args()

    results = [("python", *check_python()), ("os", *check_os()), ("docker cli", *check_docker_cli())]
    if shutil.which("docker"):
        results.append(("docker daemon", *check_docker_daemon()))
        if results[-1][1] == GO:
            results.append(("arch", *check_arch()))
            results.append(("image builder", *check_legacy_builder()))
    else:
        results.append(("docker daemon", NOGO, "skipped — docker not on PATH"))

    worst = GO
    for name, status, detail in results:
        print(f"  [{status:>5}] {name}: {detail}")
        if status == NOGO:
            worst = NOGO
        elif status == WARN and worst != NOGO:
            worst = WARN

    print()
    print("Reminder: CONTROL (the engagement dir) must be on local storage — not a "
          "network share, and not under /mnt on WSL.")
    if worst == NOGO:
        print("\nNO-GO: fix the NO-GO items above before using the harness.")
        sys.exit(1)
    print(f"\n{worst}: environment preflight passed." + ("" if worst == GO else " Review the WARN items."))

    if args.qualify:
        print(f"\nQualifying sandbox against {args.qualify} ...")
        sys.exit(subprocess.run(
            [sys.executable, "-m", "probes.canary.qualify_sandbox", "--image", args.qualify]).returncode)
    print("\nNext: python3 -m probes.canary.qualify_sandbox --image <base-image>, then see READINESS.md")


if __name__ == "__main__":
    main()
