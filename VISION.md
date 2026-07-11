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
current bounded scheduler, pager, mediated-I/O, and first Linux-personality
receipts are extended through the remaining pressure workloads and integrated
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
complete graph depth 19
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
reported complete-graph depth 17-18 across clean 16-worker runs
10 temporal-property branches checked
```

That graph checks one-shot continuation consumption and wakeup, same-page loser
resolution, generation fencing, explicit adoption, kernel-only deadline
closure, and the pager-specific safety and liveness properties documented in
`specs/cser/PAGER.md`. It does not model real locks, SMP TLB visibility, actual
tasks or address spaces, physical time, file-backed paging, COW, swap, or task
termination.

`specs/cser/IoCser.tla` is the explicit mediated-I/O refinement. Its three-ID
safety graph uses request symmetry and checks no temporal formulas; TLC explored
21,998,796 generated states, 4,151,240 distinct states, depth 39, and left zero
states queued. A separate two-ID graph deliberately disables symmetry and
checks five action/liveness branches; it explored 1,138,855 generated states,
269,645 distinct states, depth 29, and left zero states queued. Expected-
counterexample reachability gates additionally show that a budget-only register
rejection, a binding-only stale publish rejection, and mixed completion/reset
outcomes are reachable.
The two graphs are independent results and are not added together. They specify
the protocol; neither graph proves a real VirtIO reset or DMA quiescence.

`specs/cser/PersonalityCser.tla` is the bounded Stage 6A refinement for one
restartable Linux syscall personality and the two operations used by
`linux-hello`: `write` and `exit_group`. It separates the external-output
`BackendCommit` from the later guest `Reply`, preserves a committed obligation
through crash/snapshot/ready/rebind/adopt, and gives authority closure the only
fair completion path. Its two-ID safety graph explored 20,478 generated and
12,802 distinct states at depth 20; its independent one-ID action/liveness
graph explored 629 generated and 507 distinct states at depth 14. Three
coverage witnesses exercise post-commit crash recovery, one process exit with
zero resume, and revoke draining a committed write while aborting an
uncommitted syscall. These finite graphs do not model Linux ABI decoding,
guest-memory access, real output deduplication, multiple tasks or personalities,
SMP, durable recovery storage, or a concrete timeout/tombstone worker.

### Executable reference evidence

`crates/cser-model` is a `no_std + alloc`, safe-Rust executable oracle for the
core, pager, mediated-I/O, and bounded personality protocols. In addition to the baseline suite, the
pager model has 12 deterministic tests and five proptests, each configured for
64 cases. It covers three independent authority, binding, and address-space
generations; same-page coalescing; recovery snapshot fencing; deadlines; frame
ownership; and mapping publication history. The I/O model adds independent
device generations, typed lease and commit-charge accounting, `avail.idx`
publication, reset/completion races, request and queue invalidation, retained
timeout tombstones, retry, and scope-local work indexes. It has 13 deterministic
tests, four proptests configured for 64 cases, and three bounded Loom surrogate
gates. The personality model adds seven deterministic tests and three
proptests for capture/prepare, backend commit versus reply, crash/rebind/adopt,
old-binding rejection, revoke ordering, and single resume/exit/abort. These are
executable reference transitions and small interleaving models; they do not
establish the eventual production lock/atomic scheme, VirtIO transport fences,
PCI reset behavior, SMP, real device quiescence, or a complete Linux server.

### Observed OSTD evidence

The pinned OSTD/OSDK 0.18 spike under `experiments/ostd-cser-spike` observed that
Nexus can, without modifying OSTD internals:

- inject a custom `Scheduler`/`LocalRunQueue`;
- run a real `VmSpace` and `UserMode` path;
- receive a real syscall return and page-fault exception;
- fence a crashed scheduler binding, make the first fallback selection attempt
  choose the FIFO task, retain timer ticks only as diagnostics, exercise the
  epoch-2 rebind gate/transition, and reject an epoch-1 stale proposal;
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

The first spike also found a negative boundary: unmodified OSTD 0.18 does not
expose a synchronous `unmap -> IOTLB invalidate -> completion wait` operation,
and its IOMMU state is crate-private. Nexus therefore carried one small,
isolated MPL-2.0 OSTD patch in
`experiments/ostd-virtio-cser-spike`. The pinned one-CPU QEMU receipt observed
one-page ownership transfer into `PendingDmaUnmap`, real VT-d global IOTLB and
wait descriptors, retention across an injected `Pending`, hardware completion
before backing/IOVA bookkeeping release, and fresh-identity IOVA reuse only
after the acknowledgement. This closes the bounded DMA-ownership API gate for
the prototype. The probe never gave the IOVA to a device and explicitly records
`device_dma=false` and `device_reset=false`; it is not evidence of mediated
VirtIO closure, device drain/reset, SMP liveness, or a production IOMMU API.

The follow-on Stage 5B receipt now exercises the missing device-visible path on
one pinned QEMU q35/VT-d configuration. Nexus directly reuses
`virtio-drivers` 0.13 PCI transport, split queue, and block wire types behind a
fixed mediation portal. A readonly sector-0 request negotiates
`RO | VERSION_1 | ACCESS_PLATFORM`, commits at the audited `avail.idx` Release
publication, emits one separately observed PCI doorbell, completes through
three distinct non-identity IOVAs, and validates a checksummed fixture. A
software-injected reset timeout retains
transport, queue, request/queue pages, epochs, and generation in a
fail-closed tombstone; retry observes real status-zero reset before queue
retirement. A non-forgeable closure token ties that acknowledgement and queue
retirement to IOMMU teardown, and the resulting closure receipt is consumed
once to publish portal quiescence. Each of the three DMA pages is then released
only after its queued global IOTLB and ordered wait completion. A second
generation publishes without notification, crashes its binding, rejects an
actual late-notify attempt at the portal, and reaches `IndeterminateAfterReset`
rather than a fictitious cancellation. The old completion is fenced by binding
and device generation.

That is bounded emulator evidence, not a hardware-general drain result. It is
single-CPU and polling-only, masks PCI INTx, uses a shared OSTD IOMMU domain and
whole-device reset, and injects timeout in software. It does not prove MSI/MSI-X
or IRQ quiescence, SMP liveness, per-device isolation, irreversible writes,
network output, physical PCIe behavior, or a production deadline/recovery
worker.

The Stage 6A follow-on adds one bounded `linux-hello` pressure trace to the
unmodified-OSTD spike. Docker builds a reproducible static x86-64 Linux
`ET_EXEC` from the retained source; the kernel validates its program headers,
W^X layout, executable entry, and a minimal aligned Linux initial stack. The
entry RX page is initially absent, so a real instruction-fetch fault enters a
one-shot file-backed continuation. Pager v1 prepares the ELF image page and
then takes a real user fault before PTE publication; a fresh pager v2 performs
snapshot/ready/rebind/adopt, publishes one RX mapping, synchronizes the local
TLB, and resumes the same RIP once. In the same workload scope, a user-policy
task submits a scoped proposal and then faults; the kernel clears it and makes
the guest the first FIFO fallback pick on the next fallback selection attempt.
Raw timer ticks are retained only as a diagnostic because serial instrumentation
and task-exit timing make them unsuitable as a real-time bound.

The guest then traps `write` and `exit_group`. Two separately constructed
linuxd tasks run real `UserMode` dispatch probes over immutable syscall
snapshots. V1 copies the bounded write payload into kernel ownership, publishes
the serial output once, and faults before guest reply. V2 performs
snapshot/ready/rebind/adopt; its repeated backend commit is fenced as
`AlreadyCommitted`, after which it replies and resumes the guest once.
The old full-identity token is submitted through the user portal before rebind
and again after explicit adoption; stale binding, no-supervisor, wrong identity,
unknown opcode, duplicate adopt/commit/reply, and invalid exit ordering are
rejected without changing the logged semantic projection. `exit_group`
explicitly prepares its terminal reply, terminalizes the process once, and
never resumes it.

Two companion scopes run the same personality state type and transition
helpers. In scope 31, `RevokeBegin` wins before backend commit, both later user
commit and reply are rejected, kernel closure aborts the continuation and
publishes its real OSTD wake, and only then may `RevokeComplete` succeed. In
scope 32, backend commit wins first; revocation closes later user operations,
kernel closure drains the existing obligation without another output, consumes
the waker once, and then completes. An early completion attempt in each scope
returns `NotQuiescent` with no semantic mutation.

This is a bounded observation, not a complete personality: it is one CPU, one
process/thread, one lazy code page, fixed enqueue order, and one single-slot
portal; most linuxd control flow is a Rust `global_asm!` dispatch probe while
the kernel harness still performs portal/state transitions. The pager's stale
map/reply cases remain kernel predicate probes, and the queued post-crash
personality delivery is a bounded harness queue rather than an asynchronous
production portal. The companion scopes do not revoke scope 30 and do not form
a unified scheduler/pager/personality/I/O registry. There is no personality
timeout/tombstone, filesystem/network path, or mediated-VirtIO output. Five
remaining core workloads are still required before Stage 6 is complete.

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
3. **DMA ownership gate — bounded GO / Observed:** the prototype selects a
   single patched-OSTD owner and has an ownership-carrying one-page
   unmap/invalidate/poll contract with a real VT-d completion receipt. The
   upstream API, multi-page/domain policy, SMP liveness, and production patch
   disposition remain open; none of those gaps is hidden by this gate.
4. **Mediated VirtIO gate — bounded slice complete / Observed:** the audited
   `Release` publication of `avail.idx` is the first conservative `Commit`;
   the TLA+ and Rust models cover cancellation, completion, reset, timeout,
   tombstone, retry, and conditional closure for one exclusive queue. The
   pinned Stage 5B receipt observes one real `ACCESS_PLATFORM` readonly block
   request, three non-identity VT-d DMA owners, status-zero whole-device reset,
   retained reset/IOTLB tombstones, three-page request/queue invalidation,
   generation fencing, and conditional `Quiesced`. This admits the prototype to integrated
   validation; the hardware-general, IRQ, SMP, multi-client, domain-isolation,
   persistence, and real-deadline gaps remain open.
5. **Linux pressure gate — Stage 6A bounded slice complete / Observed, Stage 6
   still in progress:** the personality TLA+ and Rust refinements plus the
   pinned `linux-hello` QEMU trace establish the narrow scheduler + file-backed
   pager + post-commit personality recovery path described above. The futex,
   epoll, dynamic PIE, runtime filesystem, and runtime network core workloads
   remain unimplemented. Linux compatibility remains an evaluation vehicle.
6. **Integrated evidence gate — incremental checks exist; final Stage 7
   planned:** extend the bounded Loom gates with implementation-specific Loom
   and/or Kani checks across scheduler, pager, personality, and I/O; add a
   parameterized QEMU recovery matrix plus fixed-`N`/varying-`k` and
   fixed-`k`/varying-`N` experiments.
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
