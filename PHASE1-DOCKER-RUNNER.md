# Phase 1 — Docker sandbox runner (replaces OpenShell)

Date: 2026-10-04. Branch baseline commit: `3a52e94`.

## Why

The OpenShell adapter depended on an unqualified CLI under `/tmp`, a custom
Landlock policy document, and PyYAML to parse it. None of that ran successfully,
and the WSL host it needed was the source of days of recovery work. Plain Docker
gives the same isolation guarantees with no extra dependency and no bespoke CLI.

## What changed

| File | Change |
|---|---|
| `harness/security_runtime.py` | Rewrote `OpenShell` → `DockerSandbox`. Same `ready()/run()/stop()` interface and receipt shape. |
| `harness/security.py` | One wiring line in `main()`: `OpenShell` → `DockerSandbox`. No controller logic changed. |
| `harness/security-requirements.txt` | Emptied — no third-party dependency (PyYAML gone). |
| `harness/SECURITY-CLI.md` | Replaced OpenShell/policy text with the Docker isolation description. |
| `tests/test_security_runtime.py` | Rewrote to mock the `docker` CLI and assert the isolation argv. |

The controller (`security.py`), its `FakeRunner` tests (`test_security.py`), the
advisory model (`security_model.py`), and the G6 pilot are **unchanged**.

## Isolation contract (recorded verbatim in every receipt as `run_command` / `isolation`)

```
docker run --name <sandbox> \
  --network none --read-only \
  --tmpfs /workspace:rw,size=64m,mode=1777 --tmpfs /tmp:rw,size=64m \
  --memory 512m --memory-swap 512m --cpus 1 --pids-limit 128 \
  --user 1000:1000 --cap-drop ALL --security-opt no-new-privileges \
  <sandbox>:test python3 /test.py
```

Source + test are baked into the image (no host bind mount). Host wall timeout is
`WALL_SECONDS + 15`; on timeout the container is killed and the receipt records
`exit_code: 124, timed_out: true` with partial stdout. `stop()` validates the
managed-name regex, force-removes the container, verifies it is gone, removes the
image, and deletes the build context under a path-escape check.

## Known ceilings (deliberate, documented)

- **Child stdout is buffered in host memory before truncation** (`subprocess.run`).
  A canary must confirm the guest cannot emit more than its memory cap allows.
  Receipt output is truncated to 1 MiB (`stdout_truncated` flags it).
- **Aggregate disk** is bounded only by the two 64 MiB tmpfs sizes, not a single quota.
- **Test and target share one container** — output is evidence to assess, not
  tamper-proof attestation. (Unchanged property; hashes catch accidents, not a
  malicious controller.)

## Live qualification — NOT RUN (needs your approval, HITL)

Mocked tests prove only that the isolation flags are passed. They do **not** prove
Docker enforces them. Before any target reproduction runs, a canary set must
confirm, each with a positive control alongside the negative:

1. Network denied (loopback, DNS, `169.254.169.254`, host gateway, docker.sock)
   vs. a permitted in-container action succeeding.
2. Writes to `/source`, `/test.py`, `/etc`, `/usr` denied; `/workspace` write OK.
3. `--user 1000:1000`, `CapEff` empty, `NoNewPrivs=1`; no host PIDs visible in `/proc`.
4. Memory cap OOM-kills at >512 MiB; pid cap blocks >128; wall timeout → 124.
5. Lifecycle: detached grandchild killed on `stop`; container/image/build-dir all gone.

Each canary result is kept as evidence, keyed by image + isolation digest; a
change to either re-opens qualification.

## How to run the unit tests (mocked; no Docker, no target)

```
python -m unittest discover -s tests -p "test_security*.py" -v
```
