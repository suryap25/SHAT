# Security engagement CLI

Trusted single-operator prototype. State and evidence use SQLite; the original G6
pilot is independent. Actual execution requires a Linux host with Docker.
Controller tests also run on Windows. The Docker sandbox adapter must pass its
live isolation qualification before an engagement is described as end-to-end
qualified.

Use Linux storage for CONTROL. Run `python3 -m harness.security --control CONTROL
COMMAND` on the Docker host.

The adapter has no third-party dependencies. Execution rejects CONTROL under
`/mnt`. Each attempt runs in a container with no network, a read-only root
filesystem, a non-root user, dropped capabilities and memory/CPU/pid caps; the
exact isolation argv is recorded in the receipt. These flags are the intended
boundary, not proof of it: live isolation canaries must confirm enforcement.

| Command | Required arguments / meaning |
|---|---|
| init | --target DIR --title TEXT --authorization TEXT --image sha256:DIGEST |
| recon | --analysis JSON (author, entry_points, trust_boundaries, assumptions, paths) |
| add | --spec JSON --script PYTHON (operator-admitted test, never host executed) |
| run | --task ID; first run hunts, second repeats in a fresh sandbox |
| status | Inspect saved tasks |
| recover | Stop incomplete sandboxes; ingest saved receipts or mark interrupted |
| block | --task ID --kind PROVIDER_BLOCKED/WAITING_QUOTA/NEEDS_INPUT --reason TEXT |
| resume | --task ID --reason TEXT; explicitly re-admit interrupted/failed/blocked work |
| cancel | --task ID --reason TEXT; recover active work first |
| export | --out NEW_DIRECTORY; source, receipts, report and review prompt/template |
| import-review | --response JSON; exact current package and complete task coverage |
| decide | --package DIGEST --decision ACCEPT/REWORK --operator NAME; --acknowledge-unresolved for ACCEPT with gaps |

Task JSON requires id, title, attacker, boundary, expected and paths. Paths must
name files in the admitted snapshot. A test prints exactly one JSON object:

```json
{"outcome":"REPRODUCED","observations":{"expected":"deny","actual":"allowed"}}
```

Use NOT_REPRODUCED for a valid negative observation. Nonzero exit, invalid JSON,
missing observations and capture errors are TOOL_FAILED. Matching runs become
REVIEW_PENDING, never automatically CONFIRMED. Disagreement becomes INCONCLUSIVE.
Revised investigations use new task IDs and invalidate older review packages.

Reviewer responses require kind=INDEPENDENT_REVIEW, package_digest, reviewer,
limitations and exactly one task decision (CONFIRM/REJECT/NEEDS_EVIDENCE) with
reason per task. Confirmation requires two matching positive observations.
Report acceptance does not authorize publication, deployment or patching and does
not change an unconfirmed task into a confirmed finding. Operator identity is
attested by this trusted CLI; there is no multi-user authentication.

Active attempts block export, review and disposition until finished or recovered.
Completed NOT_REPRODUCED with REJECT means the operator-written test did not
reproduce the hypothesis; it does not establish safety. REJECT over REPRODUCED,
NEEDS_EVIDENCE and unfinished tasks require explicit acknowledgment
for report acceptance. Exports include task review decisions and the bound
disposition when present.
Disposition is immutable for a package: changing REWORK to ACCEPT requires a new
investigation revision and review, not replacement of the original decision.

Advisory local inference:

```text
python -m harness.security_model --model MODEL --prompt FILE --out NEW_FILE
```

Only loopback Ollama endpoints are admitted; proxies and redirects are disabled.
No paid API adapter, model switching or autonomous tool calls. Raw output and
prompt digest are retained. A model returning schema-valid prose still needs
semantic review; transport/schema success is not security quality qualification.

Docker tests run with `--network none`, a read-only root filesystem, size-capped
tmpfs for /workspace and /tmp, 512 MiB memory and no swap, one CPU, a 128-pid cap,
`--user 1000:1000`, `--cap-drop ALL`, `--security-opt no-new-privileges` and a
host wall timeout. The controller is trusted. The tested code and test share a
container, so generated output is evidence to assess, not independently
authenticated proof. Evidence hashes detect accidental/stale changes, not a
malicious controller rewriting its DB.

The adapter requires an image that can run `python3 /test.py`. Child stdout is
buffered in host memory before truncation, and aggregate disk is not separately
bounded beyond the tmpfs sizes. Network, filesystem, memory, pid, output and
lifecycle enforcement, and local image build/run semantics, still need live
qualification. Mocked adapter tests prove argument wiring only, not enforcement.

The first prototype supports operator-authored reconnaissance and tests. Automated
recon/hunter planning remains unqualified until the model and live runner pass.
