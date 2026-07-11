# Nexus: research vision

Status: working research contract, July 2026.

Nexus is a research operating system about containing the effects of restartable
user-space OS services. It is not a Zircon/Fuchsia reimplementation, and Linux
compatibility is not its research identity.

The central question is:

> Can a small kernel enforce one causal lifetime over the continuations, waits,
> timers, scheduling actions, page-fault resolutions, IPC operations, resource
> credits, and device I/O created by a user-space authority, so that the
> authority can be revoked or rebound after a crash without allowing stale work
> to commit or pretending that irreversible effects were rolled back?

The working mechanism is **Causally Scoped Effect Revocation (CSER)**. CSER is a
candidate contribution, not an established novelty claim. This document defines
what Nexus is trying to learn, the evidence required to support that claim, and
the work that is deliberately outside the project.

## Evidence language

Nexus documentation uses these terms deliberately:

- **Specified** means an operation and its linearization point are defined in
  the TLA+/PlusCal protocol or an explicitly identified successor spec.
- **Checked** means a bounded model checker or an implementation-level checker
  explored the stated model. It does not imply a proof of the whole system.
- **Observed** means a pinned implementation ran through a concrete test path.
- **Planned** means design intent with no implementation evidence yet.
- **Candidate contribution** means a research hypothesis that still requires a
  close prior-art comparison and experimental support.

Words such as “proved”, “safe”, “quiescent”, and “bounded” must name their model,
assumptions, and measurement. A passing QEMU trace is not a proof; a passing
finite-state model is not evidence that a device stopped DMA.

## The research hypothesis

Modern systems can move scheduling, paging, compatibility, and I/O policy out
of the kernel, but a restartable policy service leaves work behind when it
crashes. A reply capability may still be in flight. A timer may still fire. A
page-faulting thread may still be suspended. A descriptor may already be visible
to a device. Revoking only the service's ordinary handles does not necessarily
close these derived effects.

CSER treats those derived operations as effects belonging to an authority
scope. The intended system propagates the scope and its epoch through every
kernel-visible continuation or asynchronous registration. The kernel owns the
gates where an effect becomes externally committed, as well as the accounting
and cleanup required to close a scope.

The current core protocol separates:

```text
Register -> Prepare --Commit--> Committed -> Completed
    |          |                    |
    +----------+-> Cancelling       +-> Draining
                       |                    |
                       v                    v
                    Aborted             Completed
```

`Commit` is the effect's linearization point. Before it, revocation can abort
the effect. After it, the backend must complete, drain, reset, or retain an
honest tombstone; CSER does not claim to undo an external event.

The scope protocol is:

```text
Active --RevokeBegin--> Closing --RevokeComplete--> Revoked
```

`RevokeBegin` atomically closes the old authority epoch's commit gate. It can be
constant-time; cleanup proceeds through a per-scope reverse index rather than a
system-wide scan. Successful `RevokeComplete` means the closing epoch has no
nonterminal effect and no held credit. A future concrete operation that times
out must return a non-success result and retain the resources needed to remain
safe; it must not report `Revoked` merely because a deadline elapsed.

Authority lifetime and service-instance lifetime are distinct:

- the **authority epoch** changes when revocation closes a generation of the
  scope;
- the **binding epoch** changes when the currently bound supervisor crashes or
  is fenced;
- a kernel fallback remains responsible for minimum progress while no trusted
  user-space binding is ready;
- a replacement supervisor must complete a ready/rebind handshake;
- old uncommitted effects are inherited only through explicit `Adopt`, never by
  silently accepting an old reply.

## Properties Nexus intends to establish

The research claim is meaningful only if the same semantics survive across the
scheduler, pager, and mediated device I/O slices.

1. **PostRevokeCommitExclusion**: after `RevokeBegin` linearizes, an effect from
   the closing authority epoch that had not committed cannot cross `Commit`.
2. **QuiescentClosure**: a successful `RevokeComplete` implies that the closing
   epoch's effects, reply authorities, in-flight transfers, and held credits
   have reached an allowed terminal state. Hardware-backed effects additionally
   require device quiescence and completed IOMMU invalidation.
3. **WorkProportionality**: `RevokeBegin` should be `O(1)`, and closure work
   should be proportional to the affected descendants and live effects `k`, not
   to all system objects `N`.
4. **SingleTerminalization**: each effect can enter `Completed` or `Aborted` at
   most once, including under duplicate, delayed, and replayed completions.
5. **Crash/Rebind fencing**: a crashed binding cannot commit an old reply. A
   replacement can act only after rebind and can inherit an orphan only by
   explicit adoption.
6. **BudgetConservation**: CPU time, pinned pages, queue slots, I/O bytes, and
   related credits can be split, spent, returned, or retained, but not copied.
7. **Fallback progress**: loss of a user-space policy service must activate a
   small kernel-owned path that reaches a safe scheduling or terminalization
   decision without depending on the failed service.

These names describe target properties. Their current evidence is recorded
below and in `ARCHITECTURE.md`; not all of them have implementation-level
evidence yet.

## What may be original

No single ingredient below is a defensible novelty claim:

- capabilities or capability revocation;
- epoch/fencing tokens;
- reverse indexes;
- transaction commit/abort;
- asynchronous cancellation;
- default implementations or kernel fallback;
- one-shot reply authority;
- resource budgets;
- effect capabilities.

Relevant prior work includes the
[seL4](https://sel4.systems/Info/Docs/seL4-manual-latest.pdf) capability and reply
model, [VINO](https://www.usenix.org/conference/osdi-96/dealing-disaster-surviving-misbehaved-kernel-extensions)'s
contained extension calls and fallback,
[TxOS](https://doi.org/10.1145/1629575.1629591) transactions,
[Speculator](https://doi.org/10.1145/1095810.1095829) and
[Rethink the Sync](https://www.usenix.org/legacy/events/osdi06/tech/nightingale/nightingale.pdf)'s
causal dependency tracking, and
[Cornucopia](https://doi.org/10.1109/SP40000.2020.00098)'s treatment of authority
retained by asynchronous kernel facilities. Distributed fencing and
deduplication systems such as Chubby and RIFL, Atomic RPC, asynchronous I/O
cancellation, and recent resource-and-effect capability work such as
[Lingering Authority](https://arxiv.org/abs/2606.22504) also constrain the claim.
[Fuchsia Restricted Mode and Starnix RFC-0261](https://fuchsia.dev/fuchsia-src/contribute/governance/rfcs/0261_fast_and_efficient_user_space_kernel_emulation)
are especially close to Nexus's old guest-session/stop-packet/user-space
emulation path; that shape is explicitly not the new research contribution.

The candidate contribution is narrower and compositional:

> one kernel-enforced causal effect scope, with explicit commit gates,
> proportional closure, crash/rebind fencing, conserved resource credits, and
> honest device quiescence, applied uniformly to multiple restartable
> user-space OS services.

Whether that combination is new and useful will be decided only after the
bounded pager evidence is extended through mediated I/O and integrated
verification, and a fresh close comparison with prior work has been completed.
A negative result or a narrower claim is an acceptable research outcome.

## Reuse is a design requirement

Nexus should spend its originality budget on CSER, not on commodity plumbing.
The project should prefer maintained components with compatible licenses and
wrap them at the CSER boundary.

| Area | Direction | Nexus-owned boundary |
| --- | --- | --- |
| Boot, traps, tasks, VM, base synchronization | OSTD/OSDK first; use a self-owned minimal rust-osdev stack only if a documented OSTD boundary fails | CSER scope/effect semantics, user-policy portals, fallback, and any necessary audited adapter |
| VirtIO device implementation | Reuse `virtio-drivers` behind a Nexus HAL | descriptor validation, commit point, DMA ownership, cancel/drain/reset, and quiescence |
| TCP/IP | Run a reused stack such as `smoltcp` in user-space `netd` | authority propagation, queue ownership, and Linux-facing semantics |
| ELF and Linux UAPI | Reuse `object`, `linux-raw-sys`, musl, and generated bindings | mapping policy, W^X, auxv, commit, and personality behavior |
| Wire layouts | Reuse `zerocopy` or equivalent checked layout tools | scope epoch, ring close, and drain protocol |
| Initial filesystems | Reuse initramfs and read-only filesystem readers | service lifecycle and effect ownership; no writable filesystem in the kernel |
| Verification and compatibility tests | Reuse TLA+/TLC, Loom, Kani, syzkaller, LTP, kselftest, libc-test, and packetdrill where applicable | Nexus-specific models, injection points, assertions, and result interpretation |

This is a reuse policy, not a declaration that every listed dependency has
already been integrated. OSTD/OSDK 0.18 is the only foundation currently tested
by the new vertical spike.

## Non-goals

Nexus does not aim to:

- reproduce the Zircon ABI, Fuchsia component model, or Starnix architecture;
- claim that user-space syscall or fault handling is new;
- design novel boot loaders, page-table walkers, TCP/IP stacks, ELF parsers,
  VirtIO protocol implementations, or Linux constants when sound reusable work
  exists;
- provide transparent rollback of packets already transmitted, DMA already
  observed by a device, or durable writes already made visible;
- move filesystem, network, Linux compatibility, or rich scheduling policy into
  the kernel;
- prove all of OSTD or all device firmware;
- maximize Linux API coverage before the CSER mechanism is evaluated;
- preserve an obsolete Nexus API or module merely because it existed in an old
  checkout.

Git history is the archive for removed implementations. Valuable conformance
contracts, race seeds, fault cases, QEMU scenarios, and traces should be
classified and migrated as oracles; obsolete compatibility layers need not be
kept alive.

## Current evidence

### Specified and bounded-checked

`specs/cser/Cser.tla` defines the current core operations and linearization
points. With the committed finite configuration, TLC explored the complete
bounded graph with:

```text
11,122 states generated
5,457 distinct states found
0 states left on queue
complete graph depth 17
```

The checked instance covers the named safety invariants, budget conservation,
old-binding exclusion, and weakly fair scheduler fallback progress. It has one
scope generation, three one-shot effect identifiers, two scalar credits, and
bounded crash generations. It does not model payloads, real time, device
quiescence, tombstones, nested scope lineage, or resource replenishment.

`specs/cser/PagerCser.tla` is a separate pager refinement rather than a silent
change to that baseline. Its committed finite instance contains two fault/thread
identities, two frames, one contended page, one crash/rebind generation, and two
address-space generations. TLC 1.8.0 completed it with no error:

```text
17,150 states generated
7,528 distinct states found
0 states left on queue
complete graph depth 17
10 temporal-property branches checked
```

That graph checks one-shot continuation consumption and wakeup, same-page loser
resolution, generation fencing, explicit adoption, kernel-only deadline
closure, and the pager-specific safety and liveness properties documented in
`specs/cser/PAGER.md`. It does not model real locks, SMP TLB visibility, actual
tasks or address spaces, physical time, file-backed paging, COW, swap, or task
termination.

### Executable reference evidence

`crates/cser-model` is a `no_std + alloc`, safe-Rust executable oracle for the
core protocol and its pager refinement. In addition to the baseline suite, the
pager model has 12 deterministic tests and five proptests, each configured for
64 cases. It covers three independent authority, binding, and address-space
generations; same-page coalescing; recovery snapshot fencing; deadlines; frame
ownership; and mapping publication history. These are sequential executable
state transitions. Four additional Loom surrogate models check bounded
interleavings at the commit/timeout gate, adopt/timeout/stale-reply gate,
single-wake-authority gate, and three-stage closure publication gate. Those
small models support differential implementation work but do not establish the
eventual production lock/atomic scheme, an SMP page-table implementation, or a
real device.

### Observed OSTD evidence

The pinned OSTD/OSDK 0.18 spike under `experiments/ostd-cser-spike` observed that
Nexus can, without modifying OSTD internals:

- inject a custom `Scheduler`/`LocalRunQueue`;
- run a real `VmSpace` and `UserMode` path;
- receive a real syscall return and page-fault exception;
- fence a crashed scheduler binding, enter FIFO fallback within one measured
  tick, exercise the epoch-2 rebind gate/transition, and reject an epoch-1 stale
  proposal;
- wrap OSTD wait/wake and tick primitives with an effect token;
- take a real client page fault, retain a kernel-owned prepared zero frame
  across a real pager-v1 page-fault crash, advance only the pager binding epoch,
  construct a fresh pager-v2 `Task`/`VmSpace`/`UserMode`, explicitly adopt the
  fault after ready/rebind, publish one mapping, synchronize the local TLB, and
  resume the unchanged fault RIP once;
- reject old-binding and pre-rebind commit predicates before VM mutation; and
- exercise a watchdog timeout in which `Closing` and a closed reply gate are
  published first, the retained frame and local waker are dropped outside the
  state lock while credit remains held, and only then are the credit returned
  and `Revoked`/`RevokeComplete` published.

The pager result is a bounded vertical-slice observation, not a production
pager. It is single-CPU, single-client, zero-page-only, and exercises only a
local TLB synchronization path. The recovery “snapshot” is a boolean protocol
handshake, not serialized pager state, and the stale/pre-rebind rejection cases
are kernel predicate probes rather than replayed user-space capabilities. OSTD's
`Waker` is reusable, so Nexus's `FaultPhase` and terminalization gate—not the
waker—enforce one-shot authority. The public mapping path may still `unwrap` on
intermediate page-table allocation failure; the spike has no arbitrary task-kill
primitive, SMP shootdown, multi-client recovery, file-backed paging, COW, swap,
or durable pager reconstruction. The scheduler result likewise does not
establish SMP policy fairness or independently exercise the compiled
lease-expiry path.

The same spike found a negative boundary: OSTD 0.18 does not expose a synchronous
`unmap -> IOTLB invalidate -> completion wait` operation, and its IOMMU state is
crate-private. Nexus therefore fails closed and does not report DMA quiescence.

## Research gates

Work proceeds through evidence gates, not feature-count milestones.

1. **Foundation/scheduler checkpoint — complete:** core TLA+/Rust semantics,
   OSTD API fit, and the one-CPU scheduler crash/fallback vertical slice.
2. **Bounded pager gate — complete / Observed:** the separate pager spec and
   Rust oracle agree on one-shot, crash/rebind/adopt, generation, deadline, and
   closure semantics; four Loom surrogate models check its critical bounded
   publication/terminalization interleavings; pinned QEMU `recover` and
   `timeout` paths observe one real fault continuation and the three-phase
   closure ordering above. This does not close the production, multi-client,
   SMP, or full fault-injection gaps.
3. **DMA ownership gate — NO-GO / open:** obtain one auditable owner and a
   synchronous unmap/invalidate/wait contract through an upstream OSTD API, a
   small reviewed patch, or a different ownership boundary.
4. **Mediated VirtIO gate — model work may proceed; real DMA closure is blocked
   by gate 3:** encode the audited `Release` publication of `avail.idx` as the
   first conservative `Commit`; model cancellation, completion, timeout,
   tombstone, and a bounded whole-device reset for the first exclusive
   single-queue `virtio-blk-pci` device unless a queue-reset contract is
   separately negotiated and checked. A real adapter may not report `Quiesced`
   until gate 3 has one owner and a completed invalidation path.
5. **Integrated evidence gate — planned:** extend the initial pager Loom gate
   with implementation-specific Loom and/or Kani checks across scheduler,
   pager, and I/O; add QEMU fault injection for system recovery and `k`/`N`
   scaling experiments for proportional revocation.
6. **Linux pressure gate — planned:** add a deliberately bounded user-space
   Linux personality and use real workloads to stress pager, wait/timer, IPC,
   and I/O effects. Linux compatibility remains an evaluation vehicle.
7. **Contribution decision — future:** repeat the prior-art comparison, state
   only the properties supported by the evidence, report overheads and failed
   cases, and narrow or reject the CSER claim if the results require it.

Every vertical slice follows the same rule: specify the state machine and exit
criteria, implement the smallest end-to-end path, inject failures, and stop if
the evidence gate fails.

## Project success

Nexus succeeds if it produces a small, understandable mechanism and a body of
reproducible evidence that answers the research question honestly. A successful
prototype must show the same authority and terminalization semantics across at
least scheduler, pager, and mediated I/O; quantify its cost; and expose rather
than conceal the points where hardware or external state prevents closure.

Running a large Linux workload, accumulating kernel features, or resembling a
well-known production OS is not by itself success.
