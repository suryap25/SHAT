# Agentic Harness for Security (AHS)

A local-first harness for **authorized** security testing. It runs a
Recon → Hunt → Validate → independent-review → human-disposition workflow with
isolated execution and retained, hash-bound evidence — so a finding is only ever
*accepted* by a human after an independent review, never auto-confirmed.

> **Authorized use only.** AHS is for testing systems you own or have explicit
> written permission to test. You are responsible for staying within that
> authorization and your local laws and policies.

## Status

Prototype, validated once end to end on a local, source-available target.
**Field-ready for local, authorized, source-available review** (offline sandbox,
operator-authored probes). Not yet ready for live/networked, adversarial, or
autonomous testing — see [`READINESS.md`](READINESS.md) for the per-target
go/no-go checklist.

## Requirements

- **Python ≥ 3.12**
- **Docker** (Docker Desktop on macOS/Windows, Docker Engine on Linux)
- A **POSIX host**: macOS and Linux run it natively; on Windows run it inside WSL.

No third-party Python packages — the harness is standard library only.

## Quickstart

```bash
# 1. Preflight — GO/NO-GO for this machine
python3 -m harness.doctor

# 2. Qualify the sandbox — proves Docker ENFORCES isolation (18 canaries)
python3 -m harness.doctor --qualify python:3.12-slim

# 3. Run the controller test suite
python3 -m unittest discover -s tests -p "test_security*.py"
```

Then read [`SETUP.md`](SETUP.md) for per-OS setup and
[`harness/SECURITY-CLI.md`](harness/SECURITY-CLI.md) for the engagement CLI
(init → recon → add → run → export → import-review → decide).

## What's here

| Path | What |
|---|---|
| `harness/security.py` | Engagement controller: snapshots, tasks, attempts, evidence, review/disposition gates |
| `harness/security_runtime.py` | `DockerSandbox` — offline, read-only, non-root, resource-capped container execution |
| `harness/security_model.py` | Advisory local-model interface (no execution authority) |
| `harness/doctor.py` | Per-machine environment preflight |
| `probes/canary/qualify_sandbox.py` | Live isolation canaries that qualify the sandbox |
| `tests/` | Controller + runtime test suite |
| `SETUP.md`, `READINESS.md` | Setup steps and per-target go/no-go |

## Isolation

Each attempt runs in a container with `--network none`, a read-only root
filesystem, a non-root user, dropped capabilities, `no-new-privileges`, and
memory/CPU/pid caps; the exact isolation argv is recorded in every evidence
receipt. `qualify_sandbox.py` verifies Docker actually enforces these before you
trust a run.

## Claude Code skills (optional — not required)

AHS runs on Python + Docker alone and imports no agent skills. The Claude Code
skills used while developing it (e.g. a laziness/simplicity reviewer, security
reference material) are **optional** and only relevant if you want the
Claude-assisted workflow. Install them separately via Claude Code; they are not a
prerequisite for running the harness.

## License

Copyright (c) 2026 Surya. **All rights reserved.** Public for reference only; no
permission is granted to use, run, copy, modify, or distribute it without prior
written permission. See [`LICENSE`](LICENSE).

## Safety model

The controller and operator are trusted; the tested code runs only in the
sandbox. Test and target share a container, so evidence is observations to
assess, not tamper-proof attestation. Repeated execution is mechanical
validation, not semantic review. Acceptance of a report never authorizes
publication, patching, or deployment.
