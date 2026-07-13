# Stage 7B acceptance and evidence boundary

This directory freezes the inputs and decision rules for Stage 7B. Runtime
evidence is generated only by the release QEMU evaluator and the host-side
oracles wired into `./x verify`; checked-in TOML is never treated as a runtime
result.

`contract.toml` fixes the exact acceptance populations: 14 semantic race IDs,
20 QEMU fault cells, 14 structural scale points, 29 performance cases, 16
primary-source prior-art rows, and the three allowed contribution verdicts.
`cser-races.toml` maps every semantic race to live production transition source,
one implementation-source Loom harness, one or more fault cells, and explicit
positive and negative gates.

The 29 performance cases are also semantic, not merely labels: `begin` measures
only `RevokeBegin`; `complete` pre-terminalizes all `k` target effects and then
measures only `RevokeComplete`; `closure` measures begin, every selection and
terminalization, and complete; `projection` measures only `scope_projection`
against the configured retained history. Fixture construction and full
invariant reconstruction stay outside every measured interval.

The concurrency boundary is deliberately narrow:

> production transition source under a Loom-modeled outer mutex

It is not evidence that OSTD `SpinLock`, interrupt masking, SMP execution,
hardware liveness, or production scheduling fairness has been checked. The
mapping therefore rejects model-only or surrogate sources for the required
implementation-source rows.

The static validator is part of `./x check`, `./x test --quick`, and `./x
doctor`. It requires exact order as well as exact set membership, rejects unknown
TOML fields, validates every repository-relative source and harness as a regular
non-symlink file, and checks that the race-to-fault union covers all 20 cells.

`kernel/nexus-ostd/x eval-stage7b` builds a release-only evaluator, pins its
container to the first CPU in the host's `Cpus_allowed_list`, and runs QEMU with
one vCPU and single-thread TCG. The guest emits the exact 20-cell fault matrix,
14 structural scale points, 257 empty-timer samples, and 65 raw samples for each
of 29 performance cases. Fixture construction, cloning, full invariant scans,
and serial output remain outside the measured intervals. These are
guest-visible TSC observations with no thresholds or hardware-cycle claim.

The `stage7b-evidence` host gate reruns all 14 implementation-source Loom
harnesses, recomputes every scale and performance oracle, validates all 16
primary-source comparison rows and source cards, and emits the contribution
decision. The current decision is `narrow`: all central safety, fault, scale,
and measurement-protocol gates pass, but Shadow Drivers and Atomic RPC remain
primary-metadata-only rather than full-text-audited. `novel`, `first`, and
`proved` are not established. SMP, hardware cycles, lock freedom, durable
external effects, Linux breadth, and identity-preserving Stage 5B root
composition remain excluded.
The pager adapter still retains its legacy semantic mirror for the established
serial/path oracle, so full adapter equivalence is also not established; the
checked claim is about the shared transition source and its enforced commit
gate, not the complete OSTD locking/scheduling context.

Generated receipts live under `target/verification/stage7b/`; the raw QEMU log
and CPU/TCG metadata live under `kernel/nexus-ostd/artifacts/`. The verification
manifest hashes these artifacts after the complete gate succeeds. The final
research narrative remains out of scope for this stage.
