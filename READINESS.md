# AHS readiness — per-target go / no-go

Run this before each engagement. A class is **GO** only if every box in it is
checked for *this* target. Status below reflects the harness as of 2026-10-07
(one real engagement run: a single authorized engagement).

Legend: `[x]` met in general · `[ ]` must be verified per engagement · `[!]` not built yet

---

## Class 1 — Local, authorized, source-available review (offline) · **GO**

The class the harness was built for and has been validated on.

- [x] Target code is on disk and admitted as an immutable snapshot (digest-pinned)
- [x] Execution is offline (`--network none`) in a Docker sandbox
- [x] Sandbox isolation live-qualified (18/18 canaries) for the base image in use
- [x] Evidence is hashed, task/receipt-bound; restart/interrupt paths tested
- [x] Independent review + owner disposition gates enforced
- [ ] You have written authorization for this specific target
- [ ] Probes are operator-authored and read-only against the snapshot
- [ ] Base image for this engagement has passed `probes/canary/qualify_sandbox.py`

**No-go if** any unchecked box above is unmet for the target in hand.

---

## Class 2 — Live / networked target · **NO-GO**

- [!] A deliberately-scoped network policy (the sandbox is `--network none`)
- [!] Network canaries proving only the intended egress is reachable
- [!] Rate/blast-radius controls and an abort path for a live system
- [ ] Explicit written authorization naming the live endpoints and window

**Blocker:** there is no qualified networked execution path. Do not point AHS at
a running service until Class 2 is built and canaried.

---

## Class 3 — Adversarial / untrusted target code · **NO-GO**

- [!] Process/attestation separation between test harness and target
      (today they share one container — observations are forgeable by design)
- [!] A trust model that does not assume a benign controller
- [x] Container-level isolation (caps dropped, non-root, read-only, pid/mem caps)

**OK today only** for code whose provenance you trust (your own SDK). **No-go**
for hostile or unknown binaries until separation exists.

---

## Class 4 — Autonomous / model-driven recon & hunt · **NO-GO**

- [!] Local model qualified against a labelled benchmark (pos/neg/adversarial)
- [!] A planner that binds every proposed probe to the snapshot + evidence store
- [!] Tripwires: scope drift, network-reach attempts, self-contradiction → halt
- [x] Operator-authored probes (the current, manual mode) work

**Blocker:** the local model is advisory and unqualified; all recon/probes are
hand-written. Autonomy stays off until qualification + tripwires exist.

**Plan:** the build-out for these three boxes is specified in
[CLASS4-PLAN.md](CLASS4-PLAN.md) — assisted autonomy where the model *proposes* a
snapshot-bound plan and the operator approves it before the existing Class 1 path
executes it. The model never gains execution or disposition authority. Nothing in
that plan is built yet; this class stays NO-GO until its exit criteria are met.

---

## Class 5 — New base image (any class) · **CONDITIONAL**

- [ ] `python3 -m probes.canary.qualify_sandbox --image <new-image>` → 18/18
- [ ] Image is Debian-family enough to run `python3 /test.py`
- [ ] Image id recorded; receipts carry it

Canary qualification is per base image. A new image is unqualified until it passes.

---

## Class 6 — Multi-operator / scale / unattended · **NO-GO**

- [!] Operator authentication (today identity is CLI-attested, single trusted user)
- [!] Concurrency beyond one engagement / one task at a time
- [!] A host more robust than WSL + Docker Desktop (which failed hard once)

**Use** single-operator, attended, one engagement at a time.

---

## Cross-cutting (true for every class)

- [x] No publication, disclosure, patch, or deployment from the harness — all gated
- [ ] Review packages and admitted source stay **private** (they contain target
      source and webhook/credential secrets) — never commit or share publicly
- [!] Model-layer flagging is worked around, not solved: execution is off-model,
      probes are operator-authored. Autonomous offensive recon via the model is
      not a capability of this harness.

**Overall:** field-ready for Class 1. Everything else is no-go until its boxes
are built and checked.
