# AHS setup — any laptop

The harness runs on a POSIX host (macOS, Linux) directly; on Windows it runs
inside WSL. There is no bespoke per-machine install — you need Python and Docker,
then you run two preflights. `doctor.py` tells you GO / NO-GO for this machine.

## macOS (simplest — no WSL)

1. **Docker Desktop** — install, launch, wait until it says *Running*.
   Apple Silicon: Docker runs Linux containers in its VM; the harness is
   unaffected, just use arm64 / multi-arch base images (doctor prints your arch).
2. **Python ≥ 3.12** — `python3 --version` (preinstall or `brew install python`).
3. **Get the repo** and from its root run the preflight:
   ```bash
   python3 -m harness.doctor
   ```
4. If GO, qualify the sandbox (proves Docker *enforces* isolation, not just that
   it's installed):
   ```bash
   python3 -m harness.doctor --qualify python:3.12-slim
   ```
   Expect `18/18 canaries passed`.
5. Read `READINESS.md` and run only the target classes marked GO for your target.

## Linux

Same as macOS, with Docker Engine (or Desktop) instead of Docker Desktop. Your
user must be able to run `docker` (in the `docker` group or via rootless Docker).

## Windows

The harness needs a POSIX host, so run it inside **WSL Ubuntu** with Docker
Desktop's WSL integration enabled. Run `python3 -m harness.doctor` from the repo
path inside WSL (e.g. `/mnt/c/...`), but keep **CONTROL on Linux storage**
(`/home/...`), never under `/mnt` — the harness rejects `/mnt` because SQLite WAL
is unreliable there.

## What `doctor.py` checks

| Check | GO means |
|---|---|
| python | ≥ 3.12 |
| os | POSIX (Windows → NO-GO: use WSL) |
| docker cli / daemon | `docker` on PATH and the daemon reachable |
| arch | reported, so you pick matching image architectures |
| image builder | `DOCKER_BUILDKIT=0` legacy build works — **the one real portability risk** |

### The image-builder WARN (read this if it fires)

The sandbox builds each attempt image with `DOCKER_BUILDKIT=0` so `FROM
sha256:<id>` resolves the **local** pinned base image. Newer Docker Desktop
builds may be BuildKit-only, where that build fails. If doctor WARNs here, the
harness needs the tag-based fallback before it will run: tag the base image
locally, verify its id equals the pinned digest, and `FROM <tag>`. Flagged so you
hit it at setup, not mid-engagement.

## What doctor does NOT do

It reports; it never installs Docker or Python for you, and it does not touch any
engagement. Qualification (`--qualify`) is per base image — re-run it whenever you
change the base image an engagement builds from.
