# Nexus: a bounded study of Causally Scoped Effect Revocation

Status: final research synthesis for the bounded Nexus `v0.1.0` result. The
evaluated exact revision, source fingerprint, run identity, receipt digests, and
artifact digests are defined by the release bundle's `manifest.json` and
`SHA256SUMS`; this prose does not duplicate a revision that can drift from that
machine-readable authority.

## Abstract

Restartable user-space operating-system services can fail without taking every
operation they derived with them. A reply continuation may still be live, a
timer may still fire, a page-faulting task may still be suspended, or a device
may still own a published descriptor and its DMA-visible memory. Revoking the
service's ordinary handles therefore does not necessarily prevent stale work
from committing or prove that its resources are reclaimable.

Nexus studies **Causally Scoped Effect Revocation (CSER)**, a kernel mechanism
that gives these derived operations one causal lifetime. A scope and its effects
carry separate authority and service-binding epochs. The kernel owns the commit
gate, typed resource ledger, scope-local reverse indexes, minimal fallback, and
the terminalization path. Revocation closes the old authority epoch before
cleanup. Work that has not committed may abort; work that has committed must
complete, drain, reset, or retain an honest tombstone. CSER never reports an
irreversible external event as rolled back.

The evaluated prototype combines twelve bounded PlusCal/TLA+ model families,
independent safe-Rust reference models, an OSTD/OSDK kernel prototype, a pinned
VirtIO/IOMMU experiment, six fixed Linux pressure inputs, and two composition
checkpoints. The additive checkpoint places nine fresh effects in seven service
domains beneath one root authority. Stage 7B checks 14 implementation-source
races under the exact boundary **production transition source under a
Loom-modeled outer mutex**, 20 case-local fault cells, and 14 structural scale
points. It retains 29 single-vCPU, single-thread-TCG, guest-visible-TSC cases as
`Observed` measurements with no thresholds. A 16-row primary-source comparison
contains 14 full-text audits and two metadata-only rows.

The result is deliberately **narrow**. The evidence supports a fixed CSER
interaction combination in a bounded, single-CPU prototype. It does not
establish novelty, firstness, a whole-system proof, SMP behavior, hardware
cycles, lock freedom, production liveness, durable external-effect closure,
Linux breadth, a shared production fault-budget scope, or identity-preserving
same-boot composition with the Stage 5B device effect.

## 1. Problem: revoking a service is not revoking its effects

Nexus starts from a distinction between a service process and the work that the
kernel or a backend continues to hold on its behalf. Moving scheduler, pager,
Linux-personality, filesystem, network, readiness, and device policy into user
space makes those services restartable, but it does not make their asynchronous
effects process-local.

Consider four representative failure paths:

1. A scheduler policy submits a pick and then crashes. An old proposal must not
   become selectable after a replacement binding is installed, but a small
   kernel path must still make scheduling progress.
2. A pager prepares a frame and then crashes before publishing the PTE. The
   fault continuation and prepared resource survive the pager process; a new
   pager must either adopt the exact orphan or let kernel closure abort it.
3. A Linux personality commits backend output and crashes before replying to the
   guest. The replacement may finish the reply, but it must not publish the
   output twice or pretend that the first publication was canceled.
4. A VirtIO request crosses `avail.idx` publication. If reset or IOMMU
   invalidation times out, freeing its frames merely because a service handle
   was revoked would be unsafe. Ownership must remain visible until a later
   acknowledgement makes reuse honest.

These paths share a failure shape:

```text
authority delegates policy
        |
        +--> kernel/backend derives asynchronous work
                         |
service crashes ----------+--> work, reply, timer, mapping, or DMA owner remains
        |
ordinary handles revoked  +--> insufficient evidence of non-commit or quiescence
```

The research question, defined more fully in [VISION.md](VISION.md), is whether
a small kernel can impose one causal lifetime on that work while preserving
three truths at once:

- stale pre-commit work does not cross a commit boundary after revocation;
- committed work is drained or retained rather than fictitiously rolled back;
- a successful closure means the affected effects and credits really reached
  an allowed terminal state within the stated model and hardware boundary.

Linux compatibility is an evaluation vehicle for this question, not the
research identity. Nexus does not claim that user-space syscall handling,
capabilities, epochs, transactions, asynchronous cancellation, resource
budgets, or device reset are new ingredients.

## 2. Mechanism: CSER

### 2.1 Scope and effect lifetimes

A CSER scope is the unit of revocation and accounting:

```text
Active --RevokeBegin--> Closing --RevokeComplete--> Revoked
```

An asynchronous effect has a separate lifecycle:

```text
Register -> Prepare --Commit--> Committed -> Completed
    |          |                    |
    +----------+-> Cancelling       +-> Draining
                       |                    |
                       v                    v
                    Aborted             Completed
```

`Commit` is the effect's externally meaningful linearization point.
`RevokeBegin` is the scope's authority-closing linearization point. They must
serialize on the same kernel-owned gate. If `RevokeBegin` wins, an old-epoch
uncommitted effect cannot later commit. If `Commit` wins, revocation inherits a
real obligation: complete it, drain it, reset its backend, or retain a
tombstone. `RevokeComplete` is enabled only when the frozen closing cohort is
terminal and holds no credit that the selected closure semantics require to be
returned.

### 2.2 Independent generations

CSER deliberately does not overload one generation counter with unrelated
events:

- the **authority epoch** advances when `RevokeBegin` closes a scope generation;
- the **binding epoch** advances when the current service binding crashes or is
  fenced;
- domain resources may add independent address-space, inode, device, socket,
  readiness-source, and closure-revision generations.

A replacement service completes snapshot/ready/rebind before acting. It inherits
an eligible `Registered` or `Prepared` orphan only through explicit `Adopt`.
Rebind alone never makes an old token current, and committed work is not
recommitted by a replacement.

### 2.3 Accounting, indexes, and closure

Each effect owns typed credit and membership in the indexes required to find its
causal ancestors, descendants, scope, domain, task, or backend resource. Credit
can move among free, held, committed, returned, or retained dispositions, but it
cannot be copied. A timeout tombstone retains the resource credit needed to
prevent unsafe reuse.

`RevokeBegin` closes the epoch without scanning all system objects. Later
closure selects work from the affected reverse indexes and removes each live
membership once. In the bounded Stage 7B structural tuples, begin visits no
target records, selection and terminalization follow the target cohort `k`, and
unrelated/history visits remain zero. This is evidence for the implemented
target-local indexing structure, not an asymptotic proof or a production
`O(k)` timing claim.

### 2.4 Fallback and honest failure

Crash advances only the binding epoch and activates a small kernel fallback.
For scheduling, fallback chooses a deterministic runnable task while no trusted
policy binding is ready. For unresolved continuations, kernel closure produces a
bounded terminal result without depending on the failed service.

A deadline is never permission to lie. If a committed device effect cannot be
shown quiescent, the scope remains `Closing`, resources remain retained, and the
result is a timeout or indeterminate terminal observation rather than a false
`Revoked`. A later reset/IOTLB acknowledgement may invalidate the old
tombstone, advance the appropriate generation, and enable a fresh closure
receipt.

### 2.5 Target properties

The common property vocabulary is:

- **PostRevokeCommitExclusion**: an uncommitted effect from the closing
  authority epoch cannot first commit after `RevokeBegin`;
- **QuiescentClosure**: successful `RevokeComplete` implies terminal effects and
  the required credit/resource disposition within the named model;
- **SingleTerminalization**: duplicate, delayed, or replayed operations cannot
  create a second terminal result;
- **Crash/Rebind fencing**: an old binding cannot commit or reply, and a
  replacement inherits only by explicit adoption;
- **BudgetConservation**: typed credits move but are not duplicated;
- **Fallback progress**: kernel-owned fallback supplies the minimum modeled
  progress after service loss;
- **WorkProportionality**: begin should be constant work and closure should
  follow affected causal work rather than visit unrelated global objects.

The detailed data model and linearization table are in
[ARCHITECTURE.md](ARCHITECTURE.md#core-objects).

## 3. Formal semantics and executable reference models

The normative semantics live in [specs/cser/](specs/cser/README.md). The
baseline and each domain successor preserve explicit commit/revoke ordering
while adding only the state needed for that boundary.

| Model family | Added semantic boundary | Principal checked distinction |
| --- | --- | --- |
| `Cser` | baseline scope/effect protocol | authority versus binding epoch, commit versus revoke, scalar budget, fallback |
| `PagerCser` | one address-space pager scope | one-shot fault continuation, mapping generation, same-page publication, recovery deadline |
| `IoCser` | mediated device request | `avail.idx` commit, typed leases, reset/IOTLB ownership, timeout tombstone |
| `PersonalityCser` | `write` and `exit_group` | backend publication versus guest reply, process exit, crash adoption |
| `PersonalityFutexCser` | private futex predecessor | compare/enqueue, wait/wake/timer credits, recovery watchdog |
| `PersonalityFutexRequeueCser` | two-key futex successor | frozen wake/move partition, queue identity, requeue credit conservation |
| `PersonalityReadinessCser` | readiness/timeout | atomic sample-and-arm, LT/ET/ONESHOT, unique ready/timeout/revoke winner |
| `PersonalityExecCser` | executable-image replacement | invisible staging, one whole-image commit, pre/post-commit revoke split |
| `RuntimeFsCser` | personality/pager/filesystem/block graph | PTE, inode, block, and guest-reply publications with independent generations |
| `RuntimeNetCser` | personality/network/readiness graph | network commit, readiness commit, buffer ownership, guest reply |
| `CompositionCser` | frozen five-domain composition | root gate, domain-local recovery, globally ordered closure receipts, VirtIO tombstone |
| `LinuxIoCompositionCser` | additive seven-domain composition | filesystem and network branches, eight credit classes, child-first indexed closure |

TLC explores the complete state graph only for each committed finite
configuration. For example, the baseline graph contains 11,122 generated and
5,457 distinct states; runtime filesystem contains a 2,262,368 / 635,313-state
safety graph; runtime network contains a 3,698,288 / 720,002-state safety graph;
and the seven-domain successor contains a 3,723,455 / 1,225,367-state safety
graph. The latter is the union of five explicit scenario partitions, not the
abandoned all-feature Cartesian product. These results are bounded model checks,
not mathematical proofs of arbitrary graphs, payloads, locks, time, SMP, or
hardware.

The safe-Rust reference models supply independently implemented executable
oracles. They do not reuse the OSTD implementation's transition bodies. Their
deterministic sequences, bounded properties, and Loom schedules check rejection
failure-atomicity, credit conservation, generation fencing, publication and
terminalization uniqueness, recovery, and tombstone retry. This separation is
intentional: using the implementation as its own oracle would not provide an
independent refinement signal.

The repository calls these specifications **successors**, not mechanically
proved refinement mappings. Backend names such as `RecoverySnapshot`,
`RecoverNext`, `BackendCommit`, PTE publication, or `ResetAck` are documented
against the relevant abstract operation; a stronger formal-refinement claim is
not made.

## 4. OSTD implementation

Nexus is implemented as a mechanism layer over pinned OSTD/OSDK 0.18. The
kernel owns validation, commit, fencing, accounting, fallback, page-table and
DMA lifetime, and final closure. Restartable user-space services own policy and
reconstructible state. The physical source partition under
[`kernel/nexus-ostd`](kernel/nexus-ostd/README.md) separates `cser/`, `domains/`,
`personality/`, `probes/`, and Stage 7B evaluation code.

| Domain | Restartable policy or producer | Kernel-owned commit/closure boundary | Bounded implementation evidence |
| --- | --- | --- | --- |
| Scheduler | user policy proposes a runnable task | validate epochs under the run-queue gate; selected task is the scheduling commit; FIFO fallback after crash | one-CPU real `UserMode` proposal/crash/fallback/rebind/stale rejection plus Stage 7B scheduler cells |
| Pager | pager prepares a mapping response | revalidate scope, binding, address-space generation, continuation, and PTE publication atomically | real instruction/page faults, pager-v1 crash, fresh pager-v2 rebind/adopt, one local-TLB-synchronized publication |
| Personality | linuxd interprets a frozen syscall snapshot | backend publication is distinct from the later one-shot guest reply or exit terminalization | write deduplication, exit-without-resume, futex, readiness, exec, filesystem, and network receipts |
| Filesystem | bounded in-memory file service | registry commit precedes fd, inode, block, or guest-memory publication | unchanged 14-syscall runtime-filesystem ELF and four-domain recovery companion |
| Network | bounded in-memory loopback netd | network operation/buffer publication, readiness receipt, and guest reply remain distinct | unchanged 22-syscall ELF, real netd-v1 fault, netd-v2 rebind/adopt, ping/pong and half-close |
| Readiness | kernel-owned readiness core consumes source receipts | exact sample/arm and ready/timeout/revoke winner | epoll-like LT/ET/ONESHOT paths and network receipt binding |
| VirtIO/IOMMU | mediated portal owns queue/device session | `avail.idx` Release is the conservative device commit; reset, queue retirement, IOTLB completion, and frame release are ordered | separate pinned Stage 5B `virtio-blk-pci`/VT-d component receipt |

The six retained Linux core inputs are `linux-hello`, adapted Round 4 futex,
adapted Round 5 epoll, dynamic PIE, unchanged runtime filesystem, and unchanged
runtime network. The two visible adaptations correct obsolete Linux test
expectations; the other four inputs are unchanged. Their role is pressure on
the CSER boundaries, not a claim of general Linux compatibility.

Stage 7A consolidated this implementation without changing the semantics: the
primary OSTD tree moved to `kernel/nexus-ostd`, large reference/workflow modules
were decomposed, and one Docker/`./x`/xtask/CI contract became the public
acceptance surface. The reference model remains in a separate workspace and the
patched real-device experiment remains separately ordered evidence.

## 5. Cross-service composition

### 5.1 Frozen five-domain predecessor

The first composition checkpoint places scheduler, pager, personality,
readiness, and a VirtIO domain adapter beneath one root authority:

```text
root
`-- personality
    |-- pager
    |   `-- scheduler
    `-- readiness
        `-- VirtIO adapter
```

The root gate derives immutable parent edges, typed-credit transfers, domain
tokens, and local reverse-index membership failure-atomically. Each service
keeps an independent binding epoch; VirtIO also keeps an independent device
generation. Root revoke freezes the exact cohort, closes causal leaves before
parents, and accepts globally sequenced domain receipts. A committed VirtIO
timeout retains its credit and prevents root closure until retry supplies an
eligible fresh receipt.

This predecessor is intentionally frozen. It has five domains, a fixed
six-node/five-edge graph, one CPU, and no runtime filesystem or runtime network.
Its real Stage 5B device evidence comes from a separate boot and demonstrates
component consistency rather than the same effect, ticket, generation, or
timeline.

### 5.2 Additive seven-domain successor

The additive Linux I/O successor composes fresh filesystem and network branches
without rewriting the predecessor:

```text
Root
|-- FsSyscall                     Personality / Control
|   |-- PagerMap                  Pager / Memory
|   |   `-- SchedulerAction       Scheduler / CPU
|   `-- FsOp                      Filesystem / Filesystem
|       `-- BlockReq              VirtIO / DMA
`-- NetSyscall                    Personality / Control
    `-- NetOp                     Network / Network
        |-- ReadinessWait         Readiness / Readiness
        `-- BufferLease           Network / Buffer
```

The graph contains seven domains, nine effects, ten causal nodes, nine edges,
and nine credit units in eight classes. Root authority, seven service bindings,
address-space, inode, device, socket, readiness-source, and closure revisions
remain independent. Network operation and buffer visibility publish as one
bounded batch, and readiness accepts only the exact committed network receipt.
Closure freezes the nine-effect cohort and processes target-domain indexes
child-first. A block request can retain a DMA credit through timeout and release
it only after retry invalidates the old receipt.

In the OSTD composition boot, all seven bounded kernel adapters are present and
the fresh effects share one real root `EffectRegistry`. The earlier runtime
filesystem and network workload scopes have already completed and been revoked;
their receipts are same-boot prerequisites, not members of the fresh cohort.
The real Stage 5B VirtIO/DMA path remains a separate-boot component-consistency
receipt. Consequently, the successor does not preserve retained-workload effect
identity, provide registry-native multi-domain bindings, perform real DMA in
the primary boot, or establish identity-preserving Stage 5B composition.

## 6. Stage 7B evaluation

The acceptance populations and decision rules are frozen in
[`evaluation/stage7b/contract.toml`](evaluation/stage7b/contract.toml); the
evidence boundary is summarized in
[`evaluation/stage7b/README.md`](evaluation/stage7b/README.md).

### 6.1 RQ1: do implementation transition sources preserve the critical winners?

Fourteen semantic races map to live production transition source and exact Loom
harnesses through
[`evaluation/stage7b/cser-races.toml`](evaluation/stage7b/cser-races.toml).
They cover wait/wake/timeout, pager publication and recovery, one-shot
continuations, commit versus revoke, budget disposition, scheduler fallback,
and I/O publication/reset/tombstone races.

The synchronization statement is exactly:

> production transition source under a Loom-modeled outer mutex

All 14 rows are `Checked`. This does not check the OSTD `SpinLock`, interrupt
masking, SMP execution, hardware liveness, lock freedom, or production
scheduling fairness. The pager adapter also retains a legacy semantic mirror
for an established serial/path oracle, so full adapter equivalence is not
established.

### 6.2 RQ2: do injected failures produce the required bounded outcomes?

The release QEMU evaluator checks 20 cells: five scheduler, five pager, five
personality/readiness, and five Linux-I/O cases. The cells include pre/post
commit crashes, stale actions, repeated crashes, same-page faults,
ready/timeout/revoke winners, reset timeout/retry, IOTLB timeout/late ack, and
duplicate completion.

All 20 are `Checked`. Fifteen non-scheduler cells use caller-namespaced,
case-local `EffectRegistry` ledgers with nonzero credit; the same-page pager cell
uses two credits in its one ledger. The five scheduler cells carry typed
`NoCredit`/N/A witnesses tied to actual fallback picks. Thus 20/20 does not mean
one shared production scope or ledger was faulted. Atomicity between a
transition-gate object and its separate case-local Registry object under a
crash or panic is also not established.

### 6.3 RQ3: does closure visit target work rather than unrelated history?

Fourteen structural tuples vary `k` at fixed `N`, vary `N` at fixed `k`, and
vary retained history. Across all tuples:

- `RevokeBegin` visits zero target records;
- `RevokeNext` calls equal `k + 1`;
- head selections, terminalizations, completion membership checks, and target
  index removals equal `k`;
- unrelated-effect and retained-history visits equal zero;
- the target scope reaches `Revoked`.

All 14 points are `Checked`. These counters establish the selected bounded data
path, not an asymptotic theorem, a production-lock cost, or independence from
map/index lookup costs.

### 6.4 RQ4: what operation costs are observed in the pinned evaluator?

The evaluator uses a release build, one vCPU, single-thread TCG, a hot cache,
guest-visible TSC bracketed by `lfence`, disabled local preemption and IRQs
during the interval, seven warmups, 65 raw samples per case, and 257 empty-timer
samples. Fixture construction, cloning, full invariant reconstruction, JSON,
and serial I/O remain outside the measured interval. Samples are not adjusted,
and there are no thresholds.

The fixed population covers `RevokeBegin` and `RevokeComplete` at
`N=1024, k={0,1,8,32,128,512}`; full closure over the same `k` series; full
closure at `k=32, N={32,128,512,2048,4096}`; and closure plus scope projection
at `N=1024, k=32, history={0,64,1024}`. The complete receipt retains min,
median, p95, max, and every raw sample for all 29 cases.

TSC statistics are intentionally not copied into this tracked report: every
cold final acceptance run produces a fresh observation population. Numerical
tables or plots for a release must be generated from that release's accepted
`target/verification/stage7b/performance.json` and remain bound to its manifest.
The values show the shape of one TCG experiment and complement the structural
counters. They are not hardware cycles, a baseline-relative overhead, an SLA,
or evidence of production performance.

### 6.5 RQ5: what contribution boundary survives prior art and missing evidence?

The comparison matrix in
[`evaluation/stage7b/prior-art.toml`](evaluation/stage7b/prior-art.toml) fixes 16
rows and 13 comparison fields per row. Fourteen source cards were audited
against retrievable primary full text, specifications, or API documentation.
Shadow Drivers and Atomic RPC are primary-metadata-only; no mechanism details
are inferred for them. The matrix and its source cards are validated as part of
`./x verify`.

## 7. Results and claim ledger

The machine-readable result is a bounded positive result with a narrow
contribution decision:

| Gate | Result | Evidence level | Decisive qualification |
| --- | ---: | --- | --- |
| Formal specifications | 12/12 families pass | `Checked` | complete only for committed finite configurations |
| Fixed Linux core inputs | 6/6 receipts pass | `Observed` plus bounded domain checks | pressure inputs, not Linux compatibility |
| Five-domain composition | pass | `Checked` / `Observed` | fixed predecessor; real device path is separate component evidence |
| Seven-domain Linux I/O composition | pass | `Checked` / `Observed` | fresh cohort; bounded adapters; no retained-effect identity or primary-boot real DMA |
| Implementation-source concurrency | 14/14 | `Checked` | production transition source under a Loom-modeled outer mutex |
| Fault matrix | 20/20 | `Checked` | 15 case-local Registry ledgers plus five typed N/A scheduler witnesses |
| Scale structure | 14/14 | `Checked` | finite counters, not an asymptotic or production timing proof |
| Performance protocol | 29/29 | `Observed` | single-vCPU TCG raw TSC; no thresholds |
| Prior art | 16/16 rows | `Checked` as a matrix | 14 full-text, two metadata-only |
| Contribution decision | `narrow` | decision receipt | novelty, firstness, and proof are not established |

The following table is the authoritative human claim map. A result must retain
its evidence, boundary, and non-claim together.

| Claim | Evidence | Boundary | Explicit non-claim |
| --- | --- | --- | --- |
| Closing an authority epoch excludes a later first commit by its uncommitted effects | baseline/domain/composition TLC, independent Rust, race and negative-oracle gates | finite models and checked transition sources | not a proof for arbitrary code, locks, or SMP |
| Each modeled effect has one terminal disposition | twelve model families, Rust oracles, 14 race rows, one-shot receipt provenance | named finite populations and bounded implementations | not full production adapter equivalence or lock freedom |
| Crash and revoke are different events | authority/binding epochs in every successor; scheduler/pager/personality/netd recovery receipts | bounded service generations and explicit adoption | not durable service reconstruction or arbitrary repeated failure |
| Typed credit is conserved in the exercised paths | formal ledgers, Rust invariants, composition receipts, 15 nonzero-credit fault cells | fixed credit classes and case-local fault ledgers | not shared production accounting or cross-object panic atomicity |
| Kernel fallback supplies bounded progress after service loss | weak-fair formal scheduler action, one-CPU QEMU picks, five scheduler fault cells | deterministic single-CPU fallback cases | not production liveness, fairness, overload, or SMP progress |
| Device-backed closure does not free retained owners before acknowledged teardown | I/O model, Stage 5B reset/IOTLB/DMA receipt, timeout/retry oracles | one pinned q35/VT-d, exclusive queue, polling, software-injected timeout | not physical-hardware generality, IRQ quiescence, durable writes, or primary-boot real DMA |
| Runtime filesystem follows the CSER publication and recovery protocol | `RuntimeFsCser`, 15 Rust/property/Loom gates, exact 14-syscall QEMU receipt | bounded in-memory files and abstract primary-boot block owners | not VFS, persistence, permissions, namespaces, same-boot device identity, or SMP |
| Runtime network follows the CSER publication and recovery protocol | `RuntimeNetCser`, 10 deterministic + 2 property + 4 Loom gates, exact 22-syscall QEMU receipt | one in-memory IPv4 loopback connection | not TCP breadth, external packets, VirtIO-net/NIC, backpressure, or SMP |
| One root authority composes the fixed seven-domain cohort | formal successor, independent Rust/Loom, fresh OSTD root registry, strict positive/negative oracle | seven domains, nine fresh effects, fixed DAG, same-boot bounded kernel adapters | not retained-workload identity, registry-native multi-domain binding, unbounded graphs, or identity-preserving Stage 5B composition |
| Closure uses target indexes without visiting unrelated/history records in the tested tuples | 14 exact structural scale points | selected `N`, `k`, and history population | not an asymptotic `O(k)` proof or production performance bound |
| Critical implementation transitions survive the selected races | 14/14 exact race mappings and assertion-marker sets | production transition source under a Loom-modeled outer mutex | not OSTD `SpinLock`, interrupt, SMP, hardware liveness, or lock-freedom evidence |
| The reported operation samples are reproducible protocol outputs | 29 cases, 65 raw samples each, environment metadata and recomputation oracle | release single-vCPU, single-thread TCG, guest-visible TSC, no thresholds | not hardware cycles, low overhead, real-time latency, or cross-machine comparability |
| The fixed CSER interaction combination is supported as a research result | all central gates pass and all exclusions are explicit | bounded, single-CPU prototype with case-local fault evidence | not novel, first, proved, production-ready, or generally useful by itself |
| The accepted evidence set belongs to one source/run identity | start/model/complete receipts and `nexus.verification.v4` manifest | trusted workspace plus exact-revision CI trust anchor | not authentication against an actor who can rewrite ignored artifacts and invoke private tooling |

### 7.1 Complete machine boundary ledger

The accepted manifest records every boundary below. Names and values are
reproduced verbatim so that prose cannot silently widen the claim.

| Manifest boundary | Value |
| --- | --- |
| `bounded_graph` | `true` |
| `single_cpu` | `true` |
| `cross_fd_total_order_claimed` | `false` |
| `identity_preserving_stage5b_composition` | `false` |
| `runtime_filesystem` | `true` |
| `runtime_network` | `true` |
| `linux_io_composition` | `true` |
| `linux_io_composition_domains` | `7` |
| `linux_io_composition_effects` | `9` |
| `linux_io_composition_causal_nodes` | `10` |
| `linux_io_composition_causal_edges` | `9` |
| `linux_io_composition_credit_classes` | `8` |
| `linux_io_composition_credit_units` | `9` |
| `linux_io_composition_same_boot_kernel_adapters` | `true` |
| `retained_workload_identity_preserved` | `false` |
| `retained_effects_in_composition_cohort` | `false` |
| `registry_multi_domain_binding` | `false` |
| `stage5b_relation` | `component_consistency` |
| `stage5b_same_boot` | `false` |
| `real_dma_primary` | `false` |
| `stage7b_concurrency_boundary` | `production transition source under a Loom-modeled outer mutex` |
| `stage7b_concurrency_races_checked` | `14` |
| `stage7b_fault_cells_checked` | `20` |
| `stage7b_scale_points_checked` | `14` |
| `stage7b_performance_cases_observed` | `29` |
| `stage7b_performance_claim` | `Observed` |
| `stage7b_prior_art_rows_checked` | `16` |
| `stage7b_prior_art_full_text` | `14` |
| `stage7b_prior_art_metadata_only` | `2` |
| `stage7b_contribution_verdict` | `narrow` |
| `novelty_established` | `false` |
| `first_established` | `false` |
| `proved_established` | `false` |
| `smp_checked` | `false` |
| `hardware_cycles_observed` | `false` |
| `lock_freedom_established` | `false` |
| `durable_external_effects_covered` | `false` |
| `linux_breadth_established` | `false` |
| `full_production_adapter_equivalence_established` | `false` |

## 8. Related work and contribution decision

The related-work result is not that CSER invented its ingredients. The audited
matrix instead constrains where any contribution can remain:

- seL4, Cornucopia, and recent resource-and-effect capability work establish
  capability derivation/revocation, one-shot reply authority, and the need to
  find authority retained by asynchronous kernel facilities;
- VINO, CuriOS, and the Shadow Drivers topic establish extension containment,
  fallback, and restartable/recoverable OS services as prior directions;
- TxOS, Speculator, and Rethink the Sync establish transaction boundaries,
  causal dependency propagation, rollback where available, and delayed external
  publication;
- Chubby, RIFL, and Atomic RPC establish adjacent fencing, retry,
  deduplication, and retained-result questions;
- Resource Containers establish causal resource attribution independent of a
  protection domain;
- Fuchsia Restricted Mode/Starnix establishes a close user-space kernel
  execution shape that Nexus explicitly excludes from its contribution;
- `io_uring` cancellation and VirtIO reset establish too-late cancellation,
  completion observation, device reset, and queue-resource retention as prior
  interface semantics.

Fourteen of these rows are full-text-audited. For Shadow Drivers and Atomic RPC,
only publisher metadata was available to the frozen audit; the report makes no
mechanism inference from secondary summaries.

The surviving result is therefore a **fixed interaction combination**: one
kernel-enforced causal root couples commit/revoke ordering, independent
authority and binding fencing, explicit orphan adoption, typed credit
conservation, target-local closure, kernel fallback, and honest post-commit
device tombstones across multiple restartable OS-service domains. Nexus
implements and evaluates that combination under the boundaries above.

The contribution decision is `narrow`, not `support-bounded` and not `reject`.
Central safety cells did not expose a counterexample, so rejection is not
warranted. A stronger decision is not authorized because the fault budget is
case-local rather than one shared production scope, cross-object crash/panic
atomicity is unestablished, the concurrency model does not cover production
OSTD locks or SMP, device identity is not preserved across the Stage 5B
composition boundary, and two adjacent primary sources remain metadata-only.
Accordingly, **novel**, **first**, and **proved** remain `not-established`.

## 9. Limitations

### Formal boundary

All TLC claims are complete only for their finite configurations. The models do
not establish arbitrary causal DAGs, nested-scope derivation, effects depending
on multiple roots, unbounded identifiers, payloads, wall-clock deadlines,
resource replenishment, or all combinations of modeled features. Successor
consistency is documented but not mechanically proved as a refinement theorem.

### Concurrency boundary

The checked implementation statement remains **production transition source
under a Loom-modeled outer mutex**. OSTD `SpinLock`, local interrupt exclusion,
cross-CPU publication, TLB shootdown, device completion interrupts, production
scheduling, SMP liveness, and lock freedom are outside it. The pager adapter's
legacy semantic mirror also prevents a full-adapter-equivalence claim.

### Fault and accounting boundary

The 20 cells do not execute beneath one shared production fault-budget scope.
Fifteen cells use independent nonzero-credit Registry ledgers; five scheduler
cells have typed N/A credit witnesses. Crash/panic atomicity across transition
gates and those distinct Registry objects is not established. Allocation
failure, arbitrary task termination, and long repeated-failure campaigns are
not comprehensively covered.

### Composition and identity boundary

The seven-domain graph is fixed and uses fresh effects. Retained filesystem and
network workloads are prior same-boot receipts, not cohort members. The common
registry does not natively transport seven independent service bindings; those
bindings are bounded outer envelopes. Real Stage 5B DMA occurs in a separate
boot and shares neither effect, ticket, nor generation identity with the root
composition. The relationship is `component_consistency`.

### Device and external-effect boundary

The real device experiment uses one q35/VT-d configuration, one exclusive
VirtIO block queue, polling with PCI INTx masked, whole-device reset, one page
per owner, a shared OSTD IOMMU domain, and software-injected timeouts. It does
not establish MSI/MSI-X/IRQ quiescence, physical PCIe behavior, per-device
domains, multi-page/multi-client policy, hardware deadline behavior, or a
production recovery worker. Packets and durable writes already made visible may
require idempotency or application-level compensation; CSER does not undo them.

### Linux and service boundary

The six fixed inputs do not establish Linux breadth. The prototype lacks a
general VFS, persistence, permissions and namespaces, TCP/IP or external
packets, VirtIO-net/NIC integration, general shared/PI/robust futex behavior,
full epoll/fd semantics, general dynamic linking/libc, signals, multiprocess
policy, and production portals. Several control paths are bounded harness
adapters rather than full service processes.

### Evaluation boundary

The scale result is structural and finite. Performance is one release,
single-vCPU, single-thread-TCG observation with no baseline, thresholds,
hardware-cycle interpretation, multi-boot replication, or cross-machine
comparability. It cannot support a low-overhead or real-time claim. The prior-art
matrix is a fixed 16-row audit, not an exhaustive literature proof, and two rows
remain metadata-only.

## 10. Reproducibility

### 10.1 Supported workflow

The public workflow is [`./x`](x); command details and host requirements are in
the root [README.md](README.md). The complete local gate is:

```bash
./x doctor
./x test --quick
NEXUS_REBUILD=1 ./x verify
```

The cold gate rebuilds the root image and runs formatting, checks, Clippy,
tests, twelve TLA+ families, both QEMU backends, filesystem/network and both
composition oracles, the release Stage 7B evaluator, implementation-source Loom
reruns, runtime recomputation, prior-art validation, contribution decision, and
manifest sealing. CI invokes the same `./x verify` surface through
[`.github/workflows/ci.yml`](.github/workflows/ci.yml).

The root development image pins Rust 1.95.0, Java, and `tla2tools.jar` 1.8.0 by
version and digest. The kernel and device workspaces pin the OSDK image by
digest. Verification containers run without network access after their images
are built. OSDK/QEMU backends remain outside the root container, and the root
container is not given the Docker socket.

### 10.2 Evidence chain

A full run first deletes expected old evidence and writes a start record bound
to the exact revision, complete nonignored-source fingerprint, invocation,
dirty/rebuild state, per-run nonce, and a private orchestration-token hash. A
model/spec completion receipt seals the formal and reference artifacts. A final
completion receipt binds that prerequisite after the QEMU, composition, and
Stage 7B gates. The manifest recomputes the source snapshot and artifact hashes
before publication.

Generated evidence lives under `target/verification/`,
`kernel/nexus-ostd/artifacts/`, and
`experiments/ostd-virtio-cser-spike/artifacts/`. The `v0.1.0` full release
bundle preserves the repository-relative paths of all 46 manifest-listed
artifacts and adds four control records: `manifest.json`, the start record, the
model/spec completion receipt, and the full completion receipt. Those 50
payload files are accompanied by a top-level `SHA256SUMS` index, for 51 total
regular files in the release bundle. A consumer can therefore recompute both
each artifact digest recorded in the manifest and the outer release-bundle
checksums without trusting prose or filename counts.

For the release to be accepted, its `nexus.verification.v4` manifest must report
the revision targeted by the `v0.1.0` tag, `status=passed`,
`worktree_dirty=false`, `rebuild_requested=true`, `nexus_rebuild=1`, twelve
specifications, fifteen stages, and 46 artifacts. The four control records must
agree on revision, source fingerprint, invocation, rebuild state, nonce, and
orchestration-token hash. The model/spec receipt digest must be the full
receipt's prerequisite, the full receipt digest must be the manifest's
completion receipt, and all 46 artifact byte counts and SHA-256 values must
recompute exactly. Failure artifacts are diagnostic and never represent a
successful release manifest.

The receipt chain is a trusted-workspace consistency boundary, not a defense
against a malicious actor who can rewrite ignored files and invoke private
tools with arbitrary environments. Release policy and tag protection treat the
annotated `v0.1.0` tag as immutable, but a normal Git tag is technically
movable. The trust anchor therefore records the annotated tag object ID, the
exact revision named by its bundled manifest, the isolated exact-revision CI
run, and the release asset SHA-256 plus bundled `SHA256SUMS`.

### 10.3 Release sealing rule

All tracked narrative, cross-reference, release-tooling, and implementation
changes belong in the revision before it is sealed. That clean revision must
pass `NEXUS_REBUILD=1 ./x verify` and the exact pushed CI workflow. The resulting
50-payload bundle plus `SHA256SUMS` (51 total files) must then be attached to the
`v0.1.0` release, whose protected annotated tag is treated as immutable and must
point to the same revision recorded by the manifest. Editing tracked content
after sealing requires a new revision,
a new cold run, exact-revision CI, and a newly identified release; evidence from
an older run must never be relabeled.

Fresh cold runs also produce fresh TSC observations. Release tables and plots
must therefore be derived from the bundled
`target/verification/stage7b/performance.json`, not copied from an earlier run.
The sealing process changes no research boundary: unless new implementation and
evidence deliberately justify a different decision, the contribution verdict
remains `narrow` and every manifest flag above remains the claim contract.

## Conclusion

Nexus answers its research question with a bounded positive result and a
negative boundary. The positive result is that one kernel-owned causal scope
can coordinate explicit commit, crash/rebind recovery, credit accounting,
indexed closure, fallback, and honest device tombstones across a fixed
seven-domain OS-service composition, with mutually reinforcing formal,
executable, QEMU, fault, scale, and provenance evidence. The negative boundary
is equally important: the `v0.1.0` release artifact does not turn that
combination into a whole-system proof, a novelty result, an SMP design, a
production Linux or device stack, or a guarantee about irreversible external
effects.

That combination, evidence stack, and explicit refusal to overstate closure are
the complete research result of this release.
