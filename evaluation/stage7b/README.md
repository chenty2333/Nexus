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
positive and negative gates. Each row also fixes an exact machine-readable
assertion-marker set. The host runner rejects a missing, duplicate, unknown, or
reordered map marker before it accepts the corresponding exact runtime marker
set or writes a receipt.

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

OneShot continuations carry the caller's nonzero semantic identity plus an
internal process-unique gate nonce. The nonce is private, never wraps, and is
copied into the opaque token/receipt, so reconstructing the same public
`(instance_id, id, generation)` and terminal outcome cannot mint a receipt that
the original gate accepts. Receipts and gates remain non-`Clone`/non-`Copy`,
and the source/mutation gate freezes that constructor and implementation
population.

The I/O instance namespace is also checked at the real adapter boundary, not
only inside `IoGate`: `Portal` owns the PCI BDF/queue identity and creates the
private session binding. A bidirectional two-BDF negative case rejects foreign
authorities and compares both complete portal projections before any PCI or DMA
operation can run. Uniqueness across simultaneously live owners remains the
caller's explicit namespace obligation.

The fault-matrix credit evidence is intentionally case-local. Fifteen
non-scheduler cells each own one caller-namespaced, nonzero-credit
`EffectRegistry` ledger (the same-page pager cell owns two credits in its one
case-local ledger); the five scheduler cells carry typed `NoCredit`/N/A
witnesses tied to their actual fallback picks. Thus `20/20` means all twenty
fault-cell contracts were checked, not that all twenty ran through one shared
production scope or ledger. A shared production fault-budget scope and
crash/panic atomicity across a transition-gate object and its separate
case-local Registry object are not established by this evaluator.

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
and measurement-protocol gates pass, and Shadow Drivers is now full-text
audited, but Atomic RPC remains primary-metadata-only. `novel`, `first`, and
`proved` are not established. SMP, hardware cycles, lock freedom, durable
external effects, Linux breadth, and identity-preserving Stage 5B root
composition remain excluded, as do a shared production fault-budget scope and
cross-object crash/panic atomicity for the case-local fault adapters.
The pager adapter still retains its legacy semantic mirror for the established
serial/path oracle, so full adapter equivalence is also not established; the
checked claim is about the shared transition source and its enforced commit
gate, not the complete OSTD locking/scheduling context.

Generated receipts live under `target/verification/stage7b/`; the raw QEMU log
and CPU/TCG metadata live under `kernel/nexus-ostd/artifacts/`. The verification
manifest hashes these artifacts after the complete gate succeeds. The final
research narrative remains out of scope for this stage.
