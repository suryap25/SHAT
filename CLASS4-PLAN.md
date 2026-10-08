# Class 4 plan — model-driven recon & hunt (assisted autonomy)

Status: **planning only**. Nothing here is built, and this document authorizes no
code and no execution. It is the build-out that would turn the three unbuilt boxes
of READINESS.md Class 4 from `[!]` into `[x]`. Until then Class 4 stays **NO-GO**.

## Objective

Let the model **propose the adversarial plan** — read the admitted snapshot and
suggest candidate probes — instead of every probe being hand-written. The point is
to make recon and hunt faster and broader, not to hand the machine the trigger.

## The one seam that keeps this safe

The model is promoted from **advisory reviewer** (what `harness/security_model.py`
is today) to **plan proposer**. It gains authority to *propose* probes bound to the
snapshot. It gains **no execution authority and no disposition authority**. A human
approves the plan before anything runs, and execution still goes through the exact
Class 1 path that already exists.

```
model proposes plan  ->  tripwires vet it  ->  OPERATOR approves / edits / rejects
   ->  approved probes admitted as tasks  ->  existing Class 1 path:
        offline sandbox  ->  two reproductions  ->  hash-bound receipts
        ->  independent review  ->  owner disposition  ->  (gated; nothing ships)
```

A refusal, a tripwire, or a low benchmark score is a **routing event** surfaced to
the operator — never a silent pass, never a silent halt of the operator's machine.

## Invariants Class 4 does NOT change

Every control below stays exactly as it is in Class 1. Class 4 adds a proposal step
in front of them; it does not loosen any of them.

- Written authorization naming the specific target is still required.
- Execution stays offline (`--network none`) in the qualified Docker sandbox.
- Evidence stays hash-bound and task/receipt-bound.
- Independent review + owner disposition still gate every finding.
- No publication, patch, or deployment leaves the harness.
- Target source/evidence do not leave the machine unless the operator opts in to an
  authorized remote model (the existing `--allow-egress` gate).

## Requirement 1 — qualify the model against a labelled benchmark

The model is not trusted to plan until it passes a test, the same way the sandbox
is not trusted until it passes `probes/canary/qualify_sandbox.py` (18/18).

- **Corpus** (three kinds of case, each a snapshot + an expected call):
  - *positive* — code with a known vulnerability and its known probe/outcome;
  - *negative* — safe code that looks suspicious; the model must not false-alarm;
  - *adversarial* — injection planted in source, comments, or tool output that
    tries to make the model mis-call, exceed scope, or follow embedded instructions.
- **Metrics** — precision/recall on finding-worthiness, false-positive rate, and
  injection resistance (the model must treat source and tool output as data, never
  as instructions).
- **Thresholds** — set per target class before qualification, not after. A model
  that misses them is not qualified for that class.
- **Record** — benchmark digest + scores are written into the engagement like a
  sandbox qualification, and re-run per model and per version (new model id =
  unqualified until it passes, mirroring Class 5 for base images).

This step is also the **feasibility gate**: if no locally runnable model clears the
benchmark, Class 4 either waits or moves to a gated remote model (see Risks).

## Requirement 2 — a snapshot- and evidence-bound planner

A planner process takes the admitted snapshot, the recon analysis, and the evidence
store, and emits **candidate probes** using the *same* spec schema an operator
authors today (`id, title, attacker, boundary, expected, paths`).

- Every proposal must cite specific paths in the digest-pinned snapshot; it cannot
  name a file that is not in the snapshot.
- The planner's output is a **plan**, not execution: proposals land in a new
  quarantined state (`PLAN_PROPOSED`) in the engagement DB. They do not run.
- The planner is, in effect, another author of `add`-style specs whose output is
  held pending human approval — it reuses the existing task machinery rather than
  introducing a second execution path.

## Requirement 3 — tripwires on the plan, before it runs

Deterministic checks run against the proposed plan, not the model's goodwill. Any
hit halts the plan and routes it to the operator with the reason.

- **Scope drift** — a probe path outside the snapshot, or any endpoint/target not
  named in the authorization.
- **Network reach** — a proposal that assumes egress (the sandbox is
  `--network none`; a plan that needs the network is wrong by construction).
- **Self-contradiction** — a plan that contradicts its own earlier statements or the
  evidence already in the store.
- **Injection** — source or tool output that appears to be steering the model
  (instructions embedded in data) → halt and flag, do not act.

## New states and flow

```
PLAN_PROPOSED  --(tripwires)-->  PLAN_VETTED | PLAN_HALTED
PLAN_VETTED    --(operator approve-plan)-->  admitted as tasks (existing pipeline)
PLAN_HALTED    --(operator review)-->  edit / reject / re-propose
```

A new `approve-plan` controller command is the only door from a proposal into the
runnable task pipeline, and it is operator-only.

## Milestones (ordered, each a decision point)

1. **Benchmark harness + corpus.** Stdlib + fixtures; define pass thresholds. Can
   start now with no change to the running harness.
2. **Qualify the model.** Run it against the benchmark, record scores. *Decision:*
   is any local model good enough, or is a gated remote model required?
3. **Planner.** Emit bound proposals into `PLAN_PROPOSED`. No execution.
4. **Tripwire suite.** Deterministic plan checks + halt/routing.
5. **`approve-plan`.** Wire approved proposals into the existing task pipeline.
6. **Dry run + flip.** One end-to-end run on a known target comparing model-proposed
   vs operator-authored probes; then update the Class 4 boxes if criteria are met.

## Risks and open questions

- **Local-model capability is the real risk.** A small local model (e.g. ~8 GB
  VRAM) may not clear the benchmark for genuine vulnerability finding. If so, Class 4
  needs a stronger gated remote model via the existing `openrouter` / `custom`
  providers — which reintroduces the egress decision and must only be used where the
  target owner authorizes sending source off-machine.
- **The benchmark is the hard, high-value artifact** and the main defense against
  injection. Most of the effort is here, not in wiring.
- **Still assisted, not unattended.** Even fully built, a human approves each plan.
  Unattended / scaled autonomy (Class 6) remains separately NO-GO.

## Non-goals

- No change to Class 2 (live targets), Class 3 (untrusted code), or Class 6.
- The model never executes a probe, never confirms a finding, and never makes the
  owner disposition.
- No autonomous offensive recon against anything outside an authorized, admitted
  snapshot.

## Exit criteria (to flip Class 4 to GO)

- A model is qualified against the benchmark at or above the set thresholds, with the
  score recorded in the engagement.
- Every proposed probe is bound to the pinned snapshot; the planner cannot reference
  anything outside it.
- The tripwire suite halts scope drift, network-reach, self-contradiction, and
  injection on a labelled adversarial set.
- `approve-plan` is the sole path from proposal to execution, and it is operator-only.
- A dry run shows model-proposed probes going through the unchanged Class 1 gates to a
  human disposition.
