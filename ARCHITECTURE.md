# Nexus architecture

Status: architecture contract for the CSER prototype, July 2026.

This document separates the intended architecture from what the repository has
already demonstrated. The evidence terms **Specified**, **Checked**,
**Observed**, **Planned**, and **Candidate contribution** have the meanings in
`VISION.md`.

For baseline operations, `specs/cser/Cser.tla` is the semantic source of truth;
`specs/cser/PagerCser.tla`, `specs/cser/IoCser.tla`, and
`specs/cser/PersonalityCser.tla` are the explicit pager, mediated-I/O, and
bounded Linux-personality successor refinements;
`specs/cser/PersonalityFutexCser.tla` is the bounded Stage 6B.1 private-futex
successor. Stage 6B.2 adds the two-key requeue, readiness, and exec successors
and a common safe-Rust personality registry. `specs/cser/RuntimeFsCser.tla` and
`specs/cser/RuntimeNetCser.tla` are separate bounded runtime successors.
`specs/cser/CompositionCser.tla` is the explicit frozen five-domain composition
successor and includes neither runtime domain. `crates/cser-model` provides the
corresponding executable oracles.
An implementation must refine those operations or change the relevant model
first; it must not silently redefine their linearization points. Sections
marked planned extend beyond the current finite models.

## System boundary

Nexus puts policy in restartable user-space services and retains only the
mechanisms required to validate, commit, fence, account, and close their
effects.

```text
  applications                         Linux workloads (late-stage pressure test)
          |                                         |
          +-------------------+---------------------+
                              |
                    user-space OS services
          +-------------------+--------------------+
          |                   |                    |
   scheduler policy         pager              blk/net service
          |             fault replies          I/O requests
          +-------------------+--------------------+
                              |
                    typed authority portals
                              |
  +---------------------------------------------------------------+
  | Nexus mechanism layer                                        |
  | scopes and effects | epoch gates | budgets | reverse indexes  |
  | one-shot replies   | commit gates | fallback | quiescence     |
  +---------------------------------------------------------------+
                              |
  +---------------------------------------------------------------+
  | OSTD foundation and audited adapters                          |
  | boot | traps | UserMode | VmSpace | tasks | wait/timer | IRQ  |
  | frames/DMA | scheduler traits | IOMMU only with safe contract |
  +---------------------------------------------------------------+
                              |
                       CPU, memory, devices
```

The “Nexus kernel” is the Nexus mechanism layer plus the small OSTD-facing
adapters needed to enforce it. Reused OSTD mechanisms do not become research
contributions merely because Nexus calls them.

## Design rules

1. **The kernel owns irreversible boundaries.** User space may choose policy,
   but only the kernel may validate an authority token and cross a kernel,
   mapping, queue-publication, or DMA-lifetime commit point.
2. **Every asynchronous effect has an owner.** A continuation, wait, timer,
   proposal, fault reply, IPC operation, or I/O request must be registered under
   a scope before it can become live.
3. **Authority and binding are independent.** Revoking a scope closes an
   authority generation. Restarting its supervisor fences a binding generation.
4. **Inheritance is explicit.** A replacement service does not acquire old
   pending work merely by using a new process or handle. It must rebind and then
   adopt each eligible effect.
5. **Closure is local.** The kernel maintains reverse indexes from a scope to its
   live effects and descendants; revocation does not scan unrelated objects.
6. **Failure is an outcome, not a reason to lie.** If a device cannot be proven
   quiescent, Nexus retains a tombstone and resources or reports timeout. It
   never frees possibly DMA-visible memory and calls the revoke complete.
7. **Fallback is mechanism, not rich policy.** Kernel fallback is deliberately
   small and deterministic: enough to keep the machine schedulable or terminate
   an unresolved operation safely while a replacement is unavailable.
8. **One subsystem owns each hardware control plane.** Nexus and OSTD may not
   independently program the same VT-d domain or invalidation queue.

## Core objects

The following is the target data model. Fields tagged “planned” are not all
present in the current spike.

### Authority scope

```text
Scope {
    id
    state: Active | Closing | Revoked
    authority_epoch
    closing_epoch?
    binding
    live_effect_index
    child_scope_index       // planned; not in the current finite model
    budget_ledger
}
```

A scope is the revocation and accounting unit. Creating a derived asynchronous
operation propagates the current scope identity and authority epoch. Nested
scope lineage is part of the intended causal design, but the checked TLA+
instance currently contains one scope generation and does not yet establish
descendant revocation semantics.

### Supervisor binding

```text
Binding {
    binding_epoch
    state: Bound | FallbackRequired | FallbackRunning
    supervisor?
}
```

`binding_epoch` identifies a particular service binding within one active
authority epoch. It must never wrap or be silently reused. A production design
must define exhaustion as a terminal error or use an identifier width and
allocation scheme that preserves this condition.

### Effect token and record

```text
EffectToken {
    scope_id
    effect_id
    authority_epoch
    binding_epoch
    kind
}

EffectRecord {
    token
    state
    budget
    backend_resources
    terminal_count
    cleanup_strategy
}
```

Tokens exposed to user space must be unforgeable kernel handles or authenticated
references, not trusted integer structs. The simple Rust and OSTD prototype structs
are executable protocol probes, not the final security representation.

The binding epoch is checked at service-originated `Prepare`, `Commit`, reply,
and adoption boundaries. Kernel-owned cleanup may continue after the binding is
fenced; otherwise a crashed service could prevent its own revocation.

### Budget ledger

The baseline model uses one scalar consumable credit:

```text
free + held + spent = total
```

The Stage 5 I/O refinement already separates typed renewable queue-slot,
pinned-page, and DMA-byte lease credits from a nonrenewable commit charge.
Registration transfers credit into `held`; commit accounts a charge as `spent`
while renewable resource leases remain held until acknowledged teardown; abort
returns unspent and renewable credit; a tombstone retains credit until safe
cleanup. Production exchange rates, replenishment, CPU budgets, and unbounded
cross-service accounting remain planned refinements and must preserve
no-duplication.

The Stage 6B.1 private-futex successor separately accounts one renewable wait
slot, one wake-continuation credit, and one recovery-watchdog timer credit.
Mismatch consumes none; wake publication or closure returns wait/wake credit;
watchdog cancellation or closure returns timer credit. These conservation
equations are checked in the bounded TLA+ graph and executable Rust oracle, but
they are not by themselves an OSTD resource-accounting observation. The
composition successor delegates one typed credit to each of five domains under
one root ledger and returns or retains it through the same closure gate; this
is still a fixed reference/spike ledger rather than production cross-service
resource accounting.

### Tombstone

```text
Tombstone {
    scope_id
    effect_id
    closing_authority_epoch
    terminalization_generation
    backend_state
    retained_frames_or_credits
    retry_or_reset_action
}
```

A tombstone records an effect that has not reached provable hardware closure.
It rejects duplicate or stale completions and prevents retained buffers from
being reused. The Stage 5 TLA+ and Rust refinements model bounded reset and
invalidation timeout witnesses plus explicit retry, but not wall-clock time,
persistent recovery records, administrative policy, or real retained device
buffers. Those implementation obligations remain prerequisites for a real
mediated-I/O `QuiescentClosure` result.

### Prospective handoff admission profile

RFC 0002 keeps the existing `Active -> Closing -> Revoked` authority lifecycle
separate from a reversible `Open | Frozen` admission gate. Freeze requires a
prior durable intent, does not advance the authority epoch, and blocks every
transition that could alter the frozen cohort or its initial classification.
Already committed effects retain honest drain, completion, publication, and
tombstone progress. A typed abort may reopen admission; a typed commit enters
the existing irreversible closing path and fences the source principal.

The original profile remains first-round abstract research. The v2 research
lane now also checks an in-memory production `EffectRegistry` mapping and a
same-boot host-process peer that emits Nexus-native receipts. The ownership log
is still a non-equivocating, rollback-free TCB input. No host-reboot recovery
record, retained-device peer wire, joint vISA/Nexus qualification, OSTD
lock/IRQ/SMP execution, or destination activation is claimed here.

## Core protocol

### Linearization points

| Operation | Owner | Preconditions | Linearization and result |
| --- | --- | --- | --- |
| `Register` | kernel portal | scope `Active`, live current supervisor, unused effect identity, available budget | insert effect in the scope reverse index and move its budget to `held` |
| `Prepare` | service request validated by kernel | effect `Registered`, scope `Active`, live supervisor, current authority and binding | record a backend-ready but not externally committed operation |
| `Commit` | kernel/backend adapter | scope `Active`, live supervisor, effect `Prepared`, both epochs current | the single transition to `Committed`; backend-specific visibility occurs at this boundary |
| `Complete` | kernel/backend completion path | effect `Committed`, valid completion identity | transition once to `Completed` and account resources |
| `RevokeBegin` | kernel | scope `Active` | atomically record the closing epoch, advance authority epoch, close its commit gate, enter `Closing` |
| `RevokeStep` | kernel worker | one indexed closing-epoch effect is nonterminal | uncommitted work moves through cancel to `Aborted`; committed work moves through drain to `Completed` |
| `RevokeComplete` | kernel | all closing-epoch effects terminal and no held closing credit | enter `Revoked`; a timeout must return another result and must not take this transition |
| `Crash` | kernel supervisor monitor | current supervisor in an `Active` scope | advance binding epoch, clear pending service proposals, require fallback |
| `FallbackPick` | kernel | fallback required | mark fallback running; a concrete slice then performs its minimal kernel decision |
| `Rebind` | kernel after replacement ready handshake | scope `Active`, fallback running, replacement snapshot ready | bind the replacement at the already advanced binding epoch |
| `Adopt` | replacement request validated by kernel | scope `Active`, live replacement, current authority, old binding, effect still `Registered` or `Prepared` | update that one orphan to the replacement binding |

These operations are abstract atomic steps. The implementation must identify the
locks, atomics, interrupt exclusion, and memory-ordering edges that refine them.
In particular, `Commit` and `RevokeBegin` must serialize on the same scope gate;
checking an epoch and publishing a backend operation in separate unprotected
steps would violate the model.

### Revoke/crash race

`Crash` is a binding event only while the scope is `Active`. If `Crash` wins,
the binding epoch advances and kernel fallback becomes required; a subsequent
`RevokeBegin` may close the authority while fallback still supplies kernel-owned
progress. If `RevokeBegin` wins, the scope is already `Closing`: no new
supervisor lifecycle starts, and kernel-owned closure proceeds without rebind.

Only `Crash` advances the binding epoch. `Rebind` attaches a replacement to the
new epoch and does not advance it again. This distinction is necessary for
stable stale-reply fencing.

### Reverse indexes and proportional work

Each live effect is linked into exactly one owning scope index, with separate
lineage metadata for any future child scope. Terminalization removes it once.
`RevokeBegin` changes the scope gate without walking the index. Cleanup workers
consume indexed entries in bounded steps.

The target cost is:

```text
RevokeBegin                  O(1)
RevokeComplete work          O(descendants + live_effects)
unrelated global effects     not visited
```

The Rust reference model exercises the per-scope index structurally. The Stage
7B release evaluator adds fourteen fixed tuples that vary `k`, unrelated `N`,
and retained history; their checked counters follow the selected cohort while
unrelated/history visits remain zero. This finite structural evidence does not
establish an asymptotic or production `O(k)` result. Its guest-visible-TSC
samples likewise do not provide a production-lock, SMP, or hardware-cycle
`k`/`N` curve.

## Kernel/user-space responsibility

### Kernel mechanism layer

The target kernel owns:

- scope creation, derivation, authority epochs, and scope state;
- binding epochs, supervisor liveness, ready/rebind, and stale-reply rejection;
- effect registration, state transitions, reverse indexes, and terminalization;
- budget transfer and conservation checks;
- typed portals for scheduler proposals, fault continuations, waits/timers, IPC,
  and mediated I/O;
- the exact backend-specific commit point;
- a minimal scheduler fallback and a bounded safe terminalization path for
  unresolved faults;
- page-table publication and TLB synchronization after pager proposals;
- DMA pin/map lifetime, queue publication mediation, completion identity,
  drain/reset coordination, IOMMU invalidation, and buffer release;
- trace sequence numbers, fault-injection hooks, and auditable failure results.

This is the intended boundary, not a statement that all items exist today.

### User-space services

User-space services own policy and reconstructible state:

- scheduling class, priority, fairness, admission, and placement proposals;
- pager choice of backing object, eviction, read-ahead, and replacement policy;
- block/network request policy, batching, protocol stacks, and filesystems;
- Linux ABI semantics, process model, files, sockets, signals, and namespaces;
- service checkpointing and the state needed to declare a replacement ready.

A service cannot bypass a typed portal to publish an effect that the kernel
cannot attribute and close. In particular, mediated I/O does not grant an
untrusted service unrestricted ownership of queue memory, DMA mappings, or
device reset.

## Vertical slice 1: scheduler crash/fallback

Status: **Observed** for one CPU in the pinned OSTD 0.18 spike.

The user-space policy submits a proposal tagged with the current authority and
binding epochs. The kernel scheduler validates the epochs and task identity at
`Prepare`; an accepted current-supervisor proposal renews the 64-tick lease
under the same run-queue lock before publishing the pending proposal, while a
stale, absent-supervisor, or unknown-task rejection does not renew it. Selecting
the proposed runnable task is the scheduling effect's `Commit`.

The observed path is:

```text
UserMode syscall -> proposal -> Commit selected task
UserMode page fault -> policy Crash -> binding epoch 1 -> 2
first post-Crash fallback selection attempt -> kernel FIFO FallbackPick
proposal before rebind -> reject no supervisor
kernel probe exercises Rebind transition at epoch 2
epoch-1 proposal -> reject stale
```

The page fault in this slice is evidence of a real `UserMode` exception path and
is used as the scheduler policy's crash trigger. It is not a recovered pager
fault. The `Rebind` call is made by the kernel-side test probe: this slice checks
the fallback prerequisite and epoch transition, but does not start a replacement
user-space supervisor or validate snapshot/ready. The experiment also wraps
OSTD `Waiter`/`Waker` and `Jiffies` with an effect token.

The patched x86 APIC supplies a callback-completion-rearmed fixed-delay logical
tick. Its nominal conversion rate can run effectively slower in wall-clock time
under callback or IRQ-tail load. Consequently, the 64-tick lease, `Jiffies`, and
artifact tick deltas are ordering/progress diagnostics, not wall-clock
freshness, timeout, or SLO claims.

The patched first-task path has two distinct observations. On the first switch
only, OSTD completes the post-schedule VM activation and then invokes a
disabled-IRQ Nexus admission hook before `enable_local`; resumed tasks do not
repeat it. The later trampoline hook proves post-IRQ liveness before the task
closure. The current Expire slice binds only its fixed `TaskData` IDs and
role-specific VM shape at the early hook, so this is not yet production
`TaskKey`, authority-epoch, or binding-epoch admission.

Limitations:

- there is one run queue and one CPU;
- the deterministic receipt checks the first post-crash fallback selection
  attempt in this one-CPU configuration; the raw logical-tick delta is recorded
  per artifact and is not a wall-clock freshness, timeout, or SLO guarantee;
- the compiled lease-expiry branch was not independently exercised;
- no real replacement supervisor lifecycle or ready handshake is observed;
- SMP proposal races, migration, fairness, and complete scope revocation remain
  untested.

## Vertical slice 2: pager recovery

Status: **bounded slice complete / Observed** in the pinned one-CPU OSTD 0.18
experiment. This is not a production pager claim.

### Pager protocol refinement

When a user thread faults, the kernel suspends it and registers a continuation
whose token binds all three independent generations:

```text
FaultToken {
    scope, fault
    authority_epoch, binding_epoch
    address_space, address_space_generation
    thread, page, access
}

Registered -> Prepared -> Committed -> Completed
     |            |
     +------------+--Abort (Closing or stale-AS only)--> Aborted

Registered/Prepared --SatisfyMapped(current mapping)--> Completed

Adopt(Registered | Prepared): binding ownership old -> replacement;
                              fault state unchanged
```

`Crash` advances only the binding epoch, `TimeoutRevoke` advances only the
authority epoch, and an address-space mutation advances only the mapping-policy
generation. `Ready`, `Rebind`, and `Adopt` advance none of them. A prepared frame
belongs to the fault effect, not to the pager process, so it may survive a
binding crash and be adopted explicitly by a ready replacement. In the
specification and Rust oracle, `Adopt` changes only the binding ownership of a
`Registered` or `Prepared` fault; it does not create another fault state.

The pager refinement defines `Commit` as one atomic transition that revalidates
the scope state, all three generations, the replacement binding, continuation
state, frame ownership, and empty PTE slot before consuming the continuation and
publishing the mapping. `Complete` publishes one successful wake. If two faults
target the same slot and generation, only one publishes a PTE; kernel
`SatisfyMapped` completes the loser from the existing mapping and releases a
redundant frame. Address-space mutation waits for committed continuations to
complete, removes the current mapping, returns its resource credit, and retains
publication history before advancing the generation.

The first live fault arms a kernel deadline batch. Pager crash/rebind cannot
rewind it, and a fault arriving while no pager is bound fails fast rather than
joining a hidden outage queue. If an expired batch still has uncommitted work,
`TimeoutRevoke` competes with `Commit` on the same `Active` gate and kernel-owned
closure aborts or completes every member before `RevokeComplete`. The pager is
not assumed fair and no replacement is assumed to appear.

### Checked and executable evidence

- TLC completed the committed pager graph with no error: 17,150 generated
  states, 7,528 distinct states, zero queued states, reported depth 17-18
  across clean 16-worker runs, and ten checked temporal-property branches.
- The safe-Rust pager oracle has 12 deterministic tests and five proptests, each
  configured for 64 cases, covering the same-page, generation, crash/rebind,
  deadline, terminalization, frame, and credit rules.
- Four small Loom surrogate models cover commit versus timeout, adopt versus
  timeout and a stale reply, complete/abort/duplicate reply ownership of one
  wake authority, and the three-stage closure publication order. They do not
  execute the OSTD pager or prove PTE/TLB/SMP behavior.
- The pinned QEMU spike has `recover` and `timeout` scenarios. These are concrete
  implementation observations, not substitutes for the bounded model or an SMP
  concurrency check.

### Observed OSTD path

In `recover`, one client takes a real not-present read fault and waits on a
kernel-held continuation. Pager v1 prepares a kernel-owned zero frame and then
crashes through its own real page fault. The kernel advances pager binding epoch
1 to 2, retains the frame, and keeps the scheduler's FIFO fallback independent
from pager fallback. A fresh pager-v2 `Task`, `VmSpace`, and `UserMode` performs
the snapshot/ready/rebind sequence, explicitly recovers and adopts the fault,
publishes the client PTE, synchronizes the local TLB, and wakes the client once;
the unchanged RIP retries and reads zero.

In `timeout`, the observed QuiescentClosure ordering is deliberately split into
three phases:

1. under the state lock, publish `Closing`, advance authority epoch 71 to 72,
   close the reply gate, remove the frame and waker from shared state, mark
   cleanup and wake obligations in flight, and keep the frame credit held;
2. outside the lock, drop the frame, publish the abort wake, and immediately
   drop the local waker object while the scope is still `Closing`;
3. under the lock again, confirm cleanup and wake publication, return the
   credit, clear both obligations, and enter `Revoked`; emit `RevokeComplete`
   only after that transition.

The serial oracle requires one terminalization in each scenario and forbids a
timeout commit/resume, duplicate completion, panic, or scheduler-epoch change.

### Boundaries not crossed

- The target security representation is an unforgeable one-shot reply handle;
  this spike uses Nexus state predicates and a `FaultPhase` terminalization gate.
  OSTD's reusable `Waker` is not itself one-shot authority.
- The recovery snapshot is only a boolean handshake plus traced fault metadata,
  not serialized or reconstructed pager policy state.
- Pre-rebind and stale-reply rejection are kernel-invoked predicate probes, not
  delayed user-space capability messages traversing a real portal.
- The OSTD probe uses an internal `Adopted` phase marker before its single
  commit. That is an implementation refinement of the model's adopted-but-still
  uncommitted `Prepared` state, not a new normative fault state.
- The implementation is single-CPU, single-client, zero-page-only, and performs
  only local TLB synchronization. The spec/model's same-page contention and
  address-space generation changes are not exercised by the QEMU slice.
- OSTD's public map path may internally `unwrap` if intermediate page-table
  allocation fails. The spike has no arbitrary task-kill primitive, SMP
  shootdown, multi-client recovery, file-backed paging, COW, swap, eviction, or
  durable pager reconstruction.

The completed bounded gate fixes the first-slice semantics; it does not remove
the need for later system fault injection around every response boundary or for
an SMP refinement. Pager fallback remains a bounded terminalization mechanism,
not a second general pager.

## Vertical slice 3: mediated VirtIO and DMA closure

Status: **bounded protocol/model and real-device slice complete / Observed**.

The service may construct and schedule an I/O request, but a Nexus-owned portal
must validate its effect token, descriptors, budgets, pinned buffers, device,
and queue before publication.

The provisional request phases are:

```text
registered -> descriptors prepared -> queue published -> device-owned
       |               |                    |
       +---- cancel ---+                    +-> complete or drain/reset
```

For the audited `virtio-drivers` 0.13 split-queue path, descriptor and available
ring writes precede a fence and the `Release` store of `avail.idx`. A device may
poll the queue, so `avail.idx` publication—not the later notification—is the
first conservative `Commit` point. The Stage 5 model must serialize its epoch
gate with that publication; it may not claim cancellation after the device can
observe the new index.

The first device slice is provisionally one service scope with exclusive use of
one single-queue `virtio-blk-pci` device. Committed-request recovery therefore
uses a bounded whole-device reset direction unless a separately negotiated and
verified queue-reset contract exists. This is an initial isolation boundary,
not a claim that whole-device reset is suitable for shared queues.

Closure of committed I/O requires a backend-specific sequence equivalent to:

1. close the submission gate for the old authority epoch;
2. cancel requests the device cannot yet observe;
3. serialize or mask completion delivery as required by the transport;
4. drain accepted requests, or reset the relevant queue/device and wait for the
   reset contract to complete;
5. unmap the DMA mappings;
6. issue the required IOTLB invalidation and wait for hardware completion;
7. only then release or repurpose pinned frames, queue slots, and credits.

The ordering of interrupt masking and drain/poll operations is device-specific;
an adapter must show how completions are still observed while interrupts are
suppressed. A reset establishes future device state but does not roll back a
packet, remote request, or durable block write already made visible.

If any step cannot finish within the defined policy deadline, the operation
returns a timeout/retained result and creates a tombstone. `RevokeComplete`
cannot succeed while a closing-epoch DMA effect lacks proven closure.

### OSTD 0.18 IOMMU boundary

Status: **bounded three-owner, one-page-per-owner feasibility / Observed**.

The pinned pristine upstream OSTD 0.18 archive removes DMA mappings without
exposing a public synchronous IOTLB invalidation-and-completion operation. Its
invalidation/domain state is crate-private, so an external Nexus adapter cannot
safely become a second VT-d owner. The initial fail-closed probe therefore
returned `IotlbInvalidationUnavailable` and never fabricated `Quiesced`.

The prototype selected one of the three admissible ownership choices: v0.1
carried a small experiment-local MPL-2.0 patch, and v0.2 promotes that exact
audited delta into the repository-wide, hash-bound canonical overlay
`patches/ostd-0.18.0-cser.patch`, consumed by both the primary-kernel and Stage
5B build graphs. The patch adds an ownership-carrying, single-page
`begin_unmap_invalidate -> PendingDmaUnmap::poll_complete` contract. The pinned
QEMU receipt observed a real VT-d global IOTLB descriptor and wait descriptor,
an injected `Pending` retaining frame/IOVA/PADDR accounting, acknowledgement
before release, and fresh-identity IOVA reuse only after completion. OSTD
remains the sole VT-d owner; Nexus owns deadline and tombstone policy.

The same overlay supplies explicit active-high/active-low and edge/level GSI
routing, encodes polarity and trigger mode in the I/O APIC RTE, and keeps the
IRTE trigger-mode bit synchronized. The legacy API remains edge/high. The
generic `iommu_probe` adapter remains `Ostd018FailClosed`, but the later bounded
runtime-filesystem vertical slice below now calls the production VirtIO/DMA
facade in the primary kernel and consumes the ownership-carrying invalidation
completion there. That slice still polls with PCI INTx masked; it is not
interrupt-delivery, IRQ-quiescence, or SMP evidence.

A second canonical overlay pins virtio-drivers 0.13 under its upstream MIT
license. It introduces a linear fail-closed prepared queue, a unique infallible
`avail.idx` Release, and exact-buffer cancellation. The production facade above
it owns only descriptive BDF/queue/token/generation coordinates: the registry
adapter must prevalidate those coordinates and the semantic commit under one
runtime lock, then invoke the infallible hardware publication inside the same
apply boundary. Reset generation uses the same prevalidate/infallible-apply
shape. Final IOTLB closure also prevalidates identity, generation, completed
owners, and single consumption before an infallible plan clears the facade
slot inside the registry acknowledgement boundary. This is source/build
substrate until a primary same-boot adapter uses it.
The registry envelope does not by itself prevent two roots from naming one
physical function or bound a whole-function reset's blast radius. The opaque
facade `Root` grants one BDF claim and `ProductionDevice` permits one active
hardware lifecycle; any later multi-root design must preserve that singleton
outside the semantic registry.

The first Stage 5A receipt deliberately stopped before device DMA. Stage 5B now
combines the same OSTD owner with a real `ACCESS_PLATFORM` modern
`virtio-blk-pci` queue. The mediated portal owns two one-page queue mappings and
one one-page request bounce mapping. Pinned QEMU observes a readonly sector-0
request through three distinct non-identity IOVAs, separates `avail.idx`
publication from one observed PCI doorbell, performs status-zero whole-device
reset, retires the queue only after reset acknowledgement, and completes a
queued global IOTLB + ordered wait chain for all three owners before backing
release. The reset acknowledgement and queue retirement produce the
non-forgeable authority consumed by IOMMU closure; the resulting non-copyable
closure receipt is itself consumed to publish `Quiesced`. This prevents
cross-generation receipt replay. An injected reset timeout
retains the whole session in a fail-closed tombstone; an injected first IOTLB
poll likewise retains all three pages until retry. A published but unnotified
generation-2 request becomes `IndeterminateAfterReset`, and stale binding or
device-generation completion is rejected. Its actual late-notify attempt also
passes through the portal and is rejected before any PCI doorbell.

This is a GO for the bounded emulator slice, not a production IOMMU/device
contract. It uses one CPU, one exclusive queue, a shared OSTD domain,
whole-device reset and completion polling with PCI INTx masked. Timeout is
software-injected. Whether the patch is upstreamed, and the production
per-device domain, multi-page, SMP, IRQ, shared-device and real-deadline policy,
remain open.

## Linux personality

Status: **bounded Stage 6 six-input pressure gate complete / Checked and
Observed**. The Stage 6A, Stage 6B.1, and Stage 6B.2 predecessor slices below
retain their original narrower boundaries; the later runtime-filesystem and
runtime-network successors complete the fixed gate without widening those
predecessors.

The Linux personality is a user-space compatibility service. It may implement
Linux syscall dispatch, process/thread semantics, memory mappings, file
descriptors, pipes, epoll, signals, filesystems, sockets, ELF/auxv integration,
and namespaces by composing Nexus services. Linux UAPI definitions and libc are
reused rather than handwritten.

The current bounded slice executes this concrete path:

```text
retained static ELF64 ET_EXEC
  -> validated load plan and Linux initial stack
  -> lazy executable-page instruction fault
  -> pager-v1 crash -> snapshot/ready/rebind/adopt -> one RX publish/resume
  -> write capture -> prepare -> backend commit
  -> linuxd-v1 crash before guest reply
  -> snapshot/ready/rebind/adopt in fresh linuxd-v2
  -> duplicate backend commit fenced -> one reply/resume
  -> companion revoke-before-commit abort and commit-before-revoke drain
  -> exit_group prepare -> one process terminalization, no user-mode resume
```

The loader uses `object 0.39.1`; the freestanding linuxd dispatch probes use
`linux-raw-sys 0.12.1`. The guest, scheduler-policy task, code-pager v1/v2, and
linuxd v1/v2 all enter real OSTD `UserMode` paths. Portal delivery gives linuxd
an immutable syscall snapshot and no writable guest context. For `write`, the
kernel-owned serial publication is the concrete `BackendCommit`; guest reply is
a distinct later transition. A committed obligation survives the personality
crash, and v2 observes `AlreadyCommitted` rather than publishing output again.
For `exit_group`, an explicit `Prepare` moves `Captured -> ReplyPrepared`; the
later `Commit kind=exit_group` is the terminal reply, not a backend-output
commit.

One workload scope currently carries five distinct effect identities:

| Effect ID | Bounded Stage 6A use |
| --- | --- |
| 0 | scoped scheduler proposal |
| 1 | `write` syscall continuation |
| 2 | `exit_group` syscall continuation |
| 3 | lazy executable-page fault continuation |
| 4 | slice-completion waiter |

This establishes shared scope-token propagation, not shared-scope revocation
closure. The scheduler, code-pager, and personality state machines remain
separate harness-owned registries, no mediated I/O effect participates in the
boot, and scope 30 itself is not revoked in this trace. Two independent
companion scopes, 31 and 32, instantiate the same personality state and
transition helpers with effects 5 and 6. They observe `RevokeBegin` winning
before backend commit and losing after it, real waiter/waker publication,
failure-atomic post-revoke user rejection, kernel abort/drain, an early
`NotQuiescent`, and a final `RevokeComplete`. They are bounded
personality-closure refinements, not a unified cross-service registry or a
timeout/tombstone worker.

The observation is deliberately narrow: one CPU, fixed enqueue order, one
process/thread, one lazy code page, one single-slot portal, static x86-64
`ET_EXEC`, `write(1, ...)`, and `exit_group(0)`. The linuxd binaries are real
freestanding Rust artifacts, but most of their current control flow is
`global_asm!` and the kernel harness still executes portal delivery, bounded
copy-in, and protocol transitions. The recovery snapshot is a bounded
handshake, not durable service state. Personality stale/no-supervisor and
invalid-order cases now arrive as full-identity user packets and are compared
against an explicit before/after semantic projection; the v1 post-crash case
uses a bounded kernel queue populated before the crash, not a production
asynchronous portal. Code-pager stale cases remain kernel predicate probes.
The Stage 6A slice itself has no dynamic loader, PIE/TLS, fd table, filesystem, network, generic
guest-memory-fault recovery, personality concurrency, SMP, or production
capability representation. Serial output is a test backend, not mediated
VirtIO.

It is intentionally integrated after scheduler, pager, and I/O effect semantics
are independently testable. Its purpose is to create mixed real workloads—such
as a page fault plus timer plus epoll wait plus socket or file I/O—and then crash
or replace services underneath them. Initial compatibility targets must be
bounded, for example static musl programs, selected libc tests, a small shell
tool set, and focused LTP/kselftest or network workloads. “Runs Linux software”
is not the Nexus research claim. All six fixed core inputs now have bounded
Checked/Observed evidence. The separate bounded cross-service composition gate
is addressed below; its old five-domain graph does not substitute for a new
seven-domain Linux I/O composition successor.

### Stage 6B futex successor boundary

The Stage 6B.1 TLA+ and pure Rust semantics checkpoint and its bounded
OSTD/QEMU implementation slice are complete / **Observed**. The concrete slice
uses one shared guest `VmSpace`, separate waiter/waker `UserContext`s, real
personality page faults, a fresh replacement task, and kernel-owned
continuations to refine the following wait/wake recovery contract. This status
does not complete the retained futex core workload or Stage 6.

Futex wait queues are kernel-owned mechanisms, not recoverable personality
policy. A private futex key is at least `(address-space identity,
address-space generation, aligned user address)`; a naked virtual address is
not a cross-process key. A wait token additionally carries scope/effect, blocked
task, operation, expected value, authority epoch, and personality binding
epoch. A user-space wake request names its authenticated operation and key, but
the kernel selects waiters from its own key index.

For the first successor refinement, `WaitRegister` abstracts one atomic
compare-and-enqueue point. A value mismatch returns `EAGAIN`, creates no live
effect, and consumes no wait credit. A match acquires one credit and inserts one
blocked continuation into exactly one key queue. `WakeCommit` atomically claims
at most the requested count, removes those waiters from selection, and freezes
the selected set and return count. A later kernel wake publication consumes
each selected continuation once. If the personality crashes after
`WakeCommit`, a replacement may explicitly adopt the continuation, but the
kernel-owned publication path returns the already saved count. Neither path may
select or wake again, including when the saved count is zero.

The recovery watchdog is a CSER service-recovery deadline, not the Linux futex
timeout argument. The retained round4 waits pass a null timeout. After a crash,
the watchdog covers the exact orphan cohort. Rebind plus explicit adoption of
that cohort cancels the watchdog even if a correctly registered futex wait
remains queued indefinitely. Expiry instead closes authority and enters kernel
abort/closure; it never fabricates `ETIMEDOUT`.

`WakeCommit`, watchdog expiry, and `RevokeBegin` serialize at the same scope
gate. If revocation wins, later wake commit is rejected without mutation and
closure aborts the queued wait. If wake wins, closure drains the fixed wake and
reply obligations without a second selection. `RevokeComplete` additionally
requires empty key queues and blocked-task/live-effect indexes, no pending wake
publication, a terminal watchdog, and all wait/wake/timer credits returned.

Stage 6B.1 deliberately stops at one private key, one waiter, one waker,
`max_wake = 1`, and one CPU. It excludes Linux timeout/timespec handling,
signals, robust/PI/shared futexes, requeue, unmap/key invalidation, and SMP
ordering. The separate Stage 6B.2 successor adds two-key atomic
`FUTEX_REQUEUE_PRIVATE`, multiple shared-`VmSpace` guest tasks, anonymous
mapping, clone/thread exit, and an explicitly adapted full Round 4 workload.
The formal 6B.1 model word has no user-store transition; the OSTD
probe adds one guest `xchg` store, but its one-CPU fixed scenario still does not
prove lost-wakeup or SMP memory-order behavior. Futex effects also retain local
indexes beside an empty embedded Stage 6A syscall registry; they do not
establish a unified syscall/futex or cross-service reverse index.

### Stage 6B.2 personality-local effect registry and futex core

The successor common registry is the single authority/binding and accounting
owner for the new personality refinements. Each effect has an immutable
six-argument syscall descriptor, an opaque full-identity handle, immutable
origin resources, mutable current resources, typed credit, and membership in
scope/task/resource reverse indexes. `commit_with_moves` validates an entire
batch before changing any phase, credit, or resource membership. Publication
is a separate one-shot ticket/ack boundary. Crash snapshots an exact cohort;
replacement readiness and rebind do not inherit it; each effect must be
adopted explicitly. Revocation walks the target scope's live index, drains
committed work, aborts uncommitted work, and completes only with empty indexes,
no pending publication, and returned credits.

Committed receipts remain kernel-owned after a crash. Kernel completion may
terminalize one without waiting for a replacement; that atomically removes it
from the remaining recovery cohort, invalidates any earlier Ready proof, and
keeps its committed credit charged until publication acknowledgement. A fresh
snapshot therefore describes only the work still needing adoption or kernel
completion and cannot return a terminal orphan from `RecoverNext`.

Futex queues remain kernel-owned domain state. A requeue receipt freezes a
disjoint FIFO wake/move partition, Linux affected count, and source/target
identity at the common commit point. Moving a waiter changes only its current
resource and typed queue membership; origin, effect identity, continuation,
credit, and prior migration history do not change. A new binding cannot skip
an unadopted old-binding queue head to select a later current-binding waiter.

Pinned QEMU executes the adapted retained Round 4 program with eight mapped
pages, three clone tasks, four waits, two wakes, and one two-key requeue whose
receipt is `woken=1`, `moved=1`, `affected=2`. Personality v1 crashes after
commit but before publication. Fresh v2 adopts exactly three effects, while a
real v1 replay is rejected against an unchanged scope/effect/resource/queue
projection. Publication occurs once, a later target wake selects the migrated
waiter, and both commit-before-close and close-before-commit companions reach
quiescence. This closes the bounded futex core input, not Linux timeout,
shared/PI/robust futexes, unmap invalidation, or SMP lost-wakeup behavior.

### Stage 6B.2 readiness and epoll boundary

Readiness sources, ready sets, and subscriptions are generational kernel-owned
objects. Subscription attach atomically samples the current source mask and
arms LT, ET, or ONESHOT observation. Source updates carry a monotonic sequence;
`MOD` advances the subscription generation; stale source-service,
subscription, or source handles reject without state mutation. A wait and
positive timer register in one batch. Ready publication, timeout, and revoke
serialize at the scope gate and freeze one immutable terminal delivery; later
source changes cannot rewrite it.

The lifecycle companion recovers six effects through snapshot/rebind/explicit
adoption, publishes a pre-crash frozen delivery once, and exercises each
ready/timeout/revoke winner with final index and credit closure. Source/queue
changes invalidate both stale snapshots and an issued Ready proof, while a new
binding cannot select an old subscription until it is explicitly adopted. The adapted
retained Round 5 input then executes pipe edge-triggered and one-shot behavior,
socketpair level-triggered behavior, empty zero-timeout waits, and Linux's
regular-file `EPERM`. Its fixed `/bin/linux-hello` lookup is an in-memory test
artifact, not runtime filesystem evidence. Full fd semantics, asynchronous
interrupt delivery, filesystem/network readiness, and SMP remain outside the
slice.

### Stage 6B.2 failure-atomic exec and dynamic PIE boundary

Exec staging is kernel-private. The transaction controller, all `PT_LOAD`
mapping effects, TLS/TCB, and initial stack must validate and be explicitly
owned by the current binding before one atomic `ExecCommit`. Nothing staged is
visible in the current process image. If revoke wins before commit, the old
image remains current; if commit wins, closure drains the committed image and
never restores the old one. The concrete `VmSpace` swap occurs outside the
registry lock only after the immutable commit receipt exists.

Pinned QEMU observes a fixed ET_EXEC launcher really issue `execve`, then
stages an ET_DYN main and ET_DYN interpreter at deterministic biases. Eight
`PT_LOAD` effects plus TLS/TCB, stack, and the transaction survive a pre-commit
personality crash and require eleven explicit adoptions. Exactly one
ExecCommit publishes the fresh `VmSpace`; old-binding attempts before and after
commit leave the full registry/image projection unchanged. The interpreter and
main check richer auxv and both TLS images, then exact write/exit publications
return all credits. `FsBase::load/save` is explicit around `UserMode::execute`,
but `UserContext` does not own FS base, so the claim is limited to one CPU and
one TLS-bearing task. General relocations, shared libraries, libc/ld.so,
filesystem-backed loading, multi-task TLS, and SMP are not established.

### Stage 6 runtime-filesystem successor boundary

The runtime-filesystem successor is **Checked and bounded OSTD/QEMU Observed**.
It extends, rather than rewrites, the Stage 6B.2 personality registry. The
formal `RuntimeFsCser` graph is fixed as
`Root -> Syscall -> {PagerMap, FsOperation -> BlockRequest}` with independently
fenced personality, pager, filesystem, and block bindings; separate root,
address-space, inode, and device generations; four typed credits; and distinct
PTE, inode, `avail.idx`, and guest-reply publication points. Its reject-enabled
safety graph has 2,262,368 generated / 635,313 distinct states at depth 35; the
action graph has 80,108 generated / 44,768 distinct states at depth 29. Eight
required witnesses cover both write/revoke orders, recovery in each derived
service path, both DMA-timeout stages, and stale-token fencing.

The independent safe-Rust oracle implements the same fixed four-effect graph.
Its deterministic, property, and Loom gates cover normal child-first closure,
write-before-revoke and revoke-before-write, explicit pager/filesystem adoption,
post-commit device drain, one-shot reply closure, reset and IOTLB tombstones,
typed-credit conservation, and failure-atomic rejection across every generation.
It is a protocol oracle, not the OSTD filesystem implementation.

The unchanged retained `linux-runtime-fs-smoke` source is digest-gated and built
reproducibly as a static ELF. Pinned one-CPU QEMU executes all 14 trapped Linux
syscalls: three `openat`, two `pread64`, `statx`, `newfstatat(AT_EMPTY_PATH)`,
one offset `pwrite64`, relative `/proc/self/exe` `readlinkat`, three `close`,
exact stdout, and `exit`. Every continuation crosses the common registry's
prepare/commit gate before fd, inode, or guest-memory publication, and all 14
publication tickets are acknowledged before scope closure. The bounded service
stores one executable, one temporary inode, and one procfs link in memory; it is
not a general VFS, persistent filesystem, page cache, permission model, or
namespace implementation.

The retained Stage 6 lifecycle companion observes distinct personality, pager,
filesystem, and block binding epochs. It requires snapshot/ready/rebind/adopt
for prepared pager and filesystem work, permits kernel completion from an
immutable post-commit receipt while the personality is absent, and checks
commit-first and revoke-first pwrite outcomes against the complete registry/
effect/domain/inode projection. Its block companion retains three abstract
owners through reset and IOTLB timeouts and releases only after acknowledgement;
that retained companion itself does not perform real DMA.

The later same-boot production-identity slice keeps the retained guest input but
replaces that abstract device relation for the first executable `pread64`. The
guest blocks with all kernel locks released while `fsd-v1` runs as registry
supervisor `TaskKey` 951:1 in an independent task and `VmSpace`. Portal entry
derives that complete key from the current OSTD `Task` rather than supplying a
runner-closure constant. V1 registers and prepares the exact filesystem child,
then queues a typed delayed `Prepare` carrying that current-task key and the old
`PortalHandle`. A real user-mode load at `0x00800000` then takes a CPU page fault
before any device preparation, commit, or guest reply. The filesystem-domain
crash freezes exactly that one prepared effect.

Only after the v1 completion waiter returns and the protocol is confirmed
`Crashed` does the slice construct the v2 `VmSpace`, v2 completion waiter/waker,
and v2 OSTD `Task`. That fresh task generation performs Snapshot -> Ready ->
Rebind -> explicit Adopt of the same effect. After adoption, v2 only triggers
delivery of the command queued by v1 before the crash: its saved v1 sender plus
old handle returns `StaleBinding`, while the same old sender plus the adopted
handle returns `NoSupervisor`. Both rejection probes leave the full Registry
projection unchanged.

Only after that recovery does the slice enroll the six-effect
`FilesystemSyscall -> FilesystemRead -> BlockRequest -> three DMA owners`
cohort. The normal lane crosses the `avail.idx` Release commit point, performs
real same-boot VirtIO/IOMMU DMA, retains owners through injected reset and IOTLB
timeouts, closes leaf-first, installs one outcome, and wakes the blocked guest
exactly once. The pre-commit lane instead lets revoke win at the device commit
gate, performs no device publication, and returns an `AbortedBeforeCommit`
result exactly once. Both lanes are strict-oracle Checked and bounded QEMU
Observed on one vCPU.

This establishes one real filesystem user-service crash point: prepared
filesystem work before device enrollment/commit. It does not observe a crash
after device commit but before guest reply, every frozen fault cell, a real IRQ,
2/4-vCPU execution, or all filesystem fault paths. The normal lane polls with
INTx masked. These observations do not close an RFC phase or establish a
general VFS, persistence, durable-write rollback, multi-client behavior, or
full production adapter equivalence.

The earlier strict host oracle remains as regression evidence. It joins the
retained Stage 6 companion to the separate Stage 5B VirtIO boot by source, ELF,
sector, and readonly-image digests, but its relation remains only
`component_consistency`: `same_boot=false`, `identity_preserving=false`. The
historical five-domain `CompositionCser` receipt likewise remains frozen with
`runtime_fs=false` and `runtime_net=false`; neither predecessor is relabeled as
the later same-boot observation.

### Stage 6 runtime-network successor boundary

The runtime-network successor is **Checked and bounded OSTD/QEMU Observed**.
Its formal graph is
`Root -> Syscall -> NetOperation -> {ReadinessWait, BufferLease}` across
independently fenced personality, network, and readiness bindings. Control,
Network, Readiness, and Buffer credits are separate, as are `NetCommit`,
`ReadyCommit`, and guest reply publication. The reject-enabled safety graph has
3,698,288 generated / 720,002 distinct states at depth 42; the action graph has
28,449 generated / 14,328 distinct states at depth 35 and checks eight temporal
branches. Eight independent witnesses cover both network/revoke orders,
network-service crash/adopt, both readiness/revoke orders, personality crash
drain/abort, retained-buffer visibility without a fabricated reply, and
full-projection stale-token fencing.

The safe-Rust successor adds ten deterministic, two property, and four Loom
gates over that fixed protocol. Pinned one-CPU QEMU executes the unchanged
retained ELF's exact 22-syscall success path with one in-memory IPv4 loopback
listener, client, and accepted socket: socket setup, exact ping/pong,
`SHUT_WR`/EOF, three closes, stdout, and exit. A real OSTD `UserMode` netd-v1
handles the first nine network operations, prepares accept, and page-faults;
netd-v2 performs snapshot/Ready/rebind/explicit adoption, rejects the stale
v1 binding without semantic mutation, commits the frozen accept, and completes
the remaining operations. Readiness remains kernel-owned, and each buffer
credit is held until peer consumption or root-owned closure.

This is one bounded listener/client/accepted-socket loopback, not smoltcp, real
TCP breadth, external packets, VirtIO-net, NIC, multi-client behavior, or SMP.
The historical `CompositionCser`/OSTD receipt remains frozen with
`runtime_fs=false` and `runtime_net=false`. The additive seven-domain Linux I/O
successor below consumes this runtime receipt only as an already-revoked
same-boot prerequisite; it does not import its effects into the new root cohort.

## Bounded system-wide CSER composition

Status: **five-domain prototype complete / Checked and Observed**, within the
bounds below.

The composition layer is an authority backbone, not a global replacement for
every domain registry:

```text
root authority scope 70
  `-- personality local registry
      |-- pager local registry
      |   `-- scheduler local registry
      `-- readiness local registry
          `-- VirtIO local registry
```

The concrete causal edges form the fixed DAG
`root -> personality -> pager -> scheduler` and
`personality -> readiness -> VirtIO`. Domain scopes 71 through 75 are local
reverse-index identities, not nested authority scopes. The one root authority
epoch, each domain binding epoch, and the VirtIO device generation remain
separate fencing dimensions.

`CompositionBackbone` owns one bounded kernel gate. Child derivation validates
the root, parent and target envelopes, then installs the immutable parent edge,
domain token, typed-credit transfer, and parent/effect/local reverse-index
membership as one failure-atomic transition. A stale parent binding is as
invalid as a stale target binding. Domain-local crash/recovery still uses each
domain's own snapshot, ready, rebind, and explicit-adopt protocol; it does not
advance peer binding epochs. TLA+ and the safe-Rust model define the general
bounded rule; the OSTD fixed-chain receipt additionally exercises
coordinator-owned exact target enrollment plus current-parent and current-target
envelope rejection.
It does not thereby establish arbitrary-graph or SMP derivation.

`RevokeBegin` advances the root authority epoch and freezes the participating
live domains and effects through that same gate. Closure selects only leaves in
the affected local indexes, so a parent cannot close while a live descendant
or retained committed obligation remains. Each accepted domain closure receipt
is bound to the revoke ticket, domain revision, binding/device generation, and
a globally unique receipt sequence. Publication is one-shot; replayed,
out-of-order, wrong-generation, and superseded timeout receipts cannot mutate
the root ledger.

A committed VirtIO timeout does not terminalize the effect or return its
credit. The root may report an honest `TimedOut` observation while remaining
`Closing`; a tombstone retains the obligation and credit. Only reset plus IOTLB
acknowledgement invalidates that tombstone, permits a fresh `Closed` receipt,
closes its causal ancestors, returns the retained credit, and allows final
`Revoked`.

The evidence has three layers:

- `CompositionCser` checks the fixed five-effect protocol, four coverage
  witnesses, and six temporal-property branches;
- the safe-Rust successor plus bounded Loom schedules check failure-atomic
  derivation, closure/receipt races, crash isolation, typed-credit conservation,
  timeout retention, and retry;
- the single-CPU OSTD receipt uses the existing scheduler, pager, personality,
  and readiness mechanisms and an external Stage 5B VirtIO adapter. A strict
  split-stream oracle checks the composition envelope against the separate
  Stage 5B guest receipts and QEMU VirtIO/DMA trace as prerequisite component
  evidence. Each stream keeps its own order; only stable owner IOVA/PADDR values
  cross the stream boundary.

The last point is not an identity-preserving refinement or a same-boot claim.
Stage 5B completes request 1 in device generation 1 and then fences generation
1 to 2; the composition adapter independently starts at generation 3 and
advances its own envelope to 4 on retry under a different effect/ticket. The
consistency oracle does not equate those identities.
Five production services do not run a mixed workload together, and real VirtIO
hardware runs in the separate Stage 5B boot. This frozen predecessor has a fixed
six-node/five-edge graph, one CPU, no runtime-filesystem or network domain, no SMP
composition proof, no system-wide parameterized fault matrix, and no `k/N` or
overhead result. The later runtime-filesystem successor above is separate
evidence and does not retroactively widen this graph.

## Additive seven-domain Linux I/O composition

Status: **bounded successor complete / Checked and Observed**, without changing
the five-domain predecessor above.

`LinuxIoCompositionCser` exhaustively checks the union of five explicit bounded
scenario partitions. Its reject-enabled safety graph completes with 3,723,455
generated / 1,225,367 distinct states at depth 55; its action graph completes
with 3,656,517 / 1,207,917 states at depth 46 and expands two liveness formulas
into three TLC branches. Ten separate reachability gates cover full closure,
both suppressed-publication splits, filesystem/network crash isolation, both
readiness/revoke orders, VirtIO reset+IOTLB tombstones, and genuinely enabled
stale-envelope/receipt/replay audits. This is exhaustive only for those five
partitions, not their abandoned all-feature Cartesian product.

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

The fixed graph has seven domains, nine effects, ten causal nodes, nine edges,
and nine credit units in eight classes; Control has capacity two. The root
authority epoch, seven binding epochs, address-space, inode, device, socket,
and readiness-source generations, and domain mutation/closure revisions remain
independent. The common OSTD registry still owns one root binding, so service
bindings are explicit bounded outer envelopes rather than a false claim that
the registry transports native multi-domain authority.

The safe-Rust model uses one clone/validate/swap gate for prepare, publication,
crash/recovery, root revoke, reverse-index terminalization, and receipt
acceptance. Network operation and buffer visibility publish as one atomic
batch; readiness accepts only the exact committed network receipt. Crash
recovery freezes an old-binding snapshot, requires `Ready`, rebinds only the
target domain, and adopts each recoverable effect explicitly. Root revoke
freezes exactly the nine-effect cohort, closes child-first by target-domain
index, and accepts globally sequenced domain receipts. A committed block request
may issue one honest `TimedOut` receipt while its effect and DMA credit remain
live; retry advances the device envelope and invalidates that receipt before a
fresh `Closed` receipt can complete revocation.

The OSTD companion creates scope 120 at authority epoch 401 and registers nine
fresh effects in one real `EffectRegistry`. It uses the real `ReadinessCore`, a
bounded in-memory inode mutation adapter, and a bounded loopback/buffer adapter.
The retained runtime-filesystem scope 95 and runtime-network scope 105 have
already reached `Revoked`; their digest-bound receipts establish only earlier
completion in the same boot. The Stage 5B VirtIO run remains a separate boot
and supplies component-consistency evidence for `avail.idx`, reset, IOTLB, and
DMA ownership. It does not share effect, ticket, or device-generation identity.

Consequently this successor is not a production multi-service authority
transport, retained-workload identity, real DMA in the primary boot,
identity-preserving Stage 5B composition, an unbounded graph, TCP/VirtIO-net
breadth, or SMP evidence.

The old guest-session/sidecar-VMO/stop-packet Starnix-like path is not the target
architecture. Tests and failure traces from it may be retained as differential
oracles after classification, but its API does not constrain the new
personality.

## OSTD adaptation boundary

### Accepted by the current spike

The pinned experiment observed public API fit for:

- custom `Scheduler` and `LocalRunQueue` injection;
- `Task`, a real `VmSpace`, and `UserMode` entry/return;
- syscall and `CpuException::PageFault` returns;
- wrappers around `Waiter`/`Waker` and `Jiffies` that retain an effect token;
- one kernel-held prepared frame across pager crash/rebind, explicit adoption,
  real PTE publication, local TLB synchronization, and the bounded timeout
  closure ordering documented above;
- one reproducibly built static Linux ELF, a validated load plan and initial
  stack, one lazy file-backed RX code-page publication, and one same-RIP
  instruction-fault resume;
- immutable Linux syscall snapshots delivered to fresh personality
  `Task`/`VmSpace`/`UserMode` instances, with a write backend commit preserved
  across crash/rebind/adopt and separated from its one guest reply;
- five unique effect IDs propagating one workload scope through scheduler,
  code-pager, personality, and completion-wait paths, without yet implementing
  a unified cross-service revoke registry in that Stage 6A trace;
- one bounded private-futex refinement with a shared guest `VmSpace`, separate
  waiter/waker contexts, atomic user-word comparison, one guest `xchg` store,
  real v1 faults, fresh-v2 rebind/adopt, watchdog cancel/expire, committed wake
  drain, uncommitted abort, strict stale-token projections, and complete
  wait/wake/timer-credit return;
- a personality-local common registry whose typed futex and generic resource
  indexes move one retained waiter atomically, plus the adapted Round 4 path
  with eight pages, three clone tasks, a frozen affected count, explicit
  recovery adoption, strict stale rejection, and quiescent closure;
- a generational readiness core with atomic sample-and-arm, LT/ET/ONESHOT,
  timeout/revoke arbitration and recovery, plus the adapted Round 5 pipe/
  socketpair/regular-file-`EPERM` execution;
- one failure-atomic dynamic exec transaction over an ET_DYN main and
  interpreter, eight `PT_LOAD` mappings, TLS/TCB and stack, with eleven explicit
  adoptions, one image commit, lock-external `VmSpace` publication, and bounded
  explicit FS-base load/save;
- through the separate Stage 5A experiment, a single-owner one-page queued
  IOTLB invalidation whose pending handle retains the real DMA owner until
  hardware completion;
- through Stage 5B, one real readonly `ACCESS_PLATFORM` VirtIO block request,
  three distinct non-identity VT-d DMA owners, one observed PCI doorbell,
  status-zero reset, fail-closed reset/IOTLB tombstones, post-reset quiet
  windows, and request plus two queue owners released only after six observed
  queued invalidation/wait chains across two device generations.
- one bounded root composition backbone that coordinates scheduler, pager,
  personality, readiness, and an external VirtIO domain adapter with one
  commit/revoke gate, failure-atomic causal derivation, typed credits,
  leaf-gated local closure, unique receipts, and timeout/tombstone/retry; the
  root split-stream oracle checks separate Stage 5B guest and QEMU reset/IOTLB
  evidence for component consistency and explicitly rejects an
  identity-preserving, cross-FD-total-order, or same-boot interpretation.

These mechanisms should be reused behind Nexus adapters. The narrow DMA/GSI
substrate hooks do not place scopes, effects, epochs, tickets, generations, or
closure policy inside OSTD; those CSER semantics remain Nexus-owned.

### Not accepted yet

- SMP scheduler protocol and cross-CPU epoch publication;
- a production one-shot continuation handle, real recovery snapshot payload,
  multi-client address-space mutation fencing, and SMP TLB shootdown;
- physical-device-general VirtIO drain/reset, MSI/MSI-X or interrupt
  quiescence, and a real-time retained recovery worker;
- multi-page mappings, per-device/domain isolation and SMP IOMMU liveness;
- an end-to-end nested authority scope implementation;
- a production syscall portal with opaque reply capabilities, durable
  personality recovery state, guest-memory copy-fault recovery, and a
  personality timeout/tombstone path;
- production network breadth, external packets, VirtIO-net/NIC integration,
  general filesystem/Linux ABI and dynamic-linker breadth, persistent or
  durable writes, production fd/epoll, multi-task personality concurrency, and
  SMP paths;
- a production/unbounded cross-service authority backbone, same-boot mixed
  service/device workload, and parameterized integrated fault matrix.

The spike also found that `qemu-direct + q35` faults before `#[ostd::main]` in
the pinned setup; the demonstrated boot path is GRUB Multiboot2 with OVMF. This
is an experiment limitation, not an architectural property to hide or build an
unsupported guarantee upon.

## Concurrency refinement

The finite protocol treats critical transitions as atomic. A real SMP
implementation must refine them with a documented synchronization scheme.
At minimum, it must establish:

- a total winner between `Commit` and `RevokeBegin` for the same scope;
- release/acquire publication of authority and binding epoch changes to every
  CPU and completion path;
- exactly-once removal from the live-effect index;
- no resurrection when a completion races cancel, reset, timeout, or adoption;
- ordering between PTE publication, TLB invalidation, and fault continuation
  consumption;
- ordering between Linux backend commitment, crash/rebind/adopt, duplicate
  commit rejection, authority closure, and the one guest reply or process exit;
- ordering between descriptor publication, device notification, completion,
  reset, IOMMU invalidation, and frame reuse.

The synchronization design is not fixed by this document. It must be small
enough to model with Loom for critical interleavings and/or Kani for bounded
state transitions. TLA+ remains responsible for abstract protocol changes;
Loom/Kani connect those abstractions to Rust implementation choices.

## Observability and fault injection

The baseline `Cser.tla` protocol names these ordered transition actions:

```text
Register Prepare Commit Complete RevokeBegin RevokeStep RevokeComplete
Crash FallbackPick Rebind Adopt
```

The Rust reference model adds `CreateScope` as an executable initialization
event. Scope creation is part of TLA+ `Init`, not a checked TLA+ transition, so
`CreateScope` must not be described as an action checked by the current TLC
graph. The OSTD prototype emits only the subset it exercises and also records
rejection outcomes such as stale or no-supervisor proposals.

The pager refinement deliberately preserves a mapping between backend-specific
names rather than pretending every artifact emits an identical trace:

| Concept | `PagerCser.tla` | Rust pager oracle | OSTD pager spike |
| --- | --- | --- | --- |
| address-space scope initialization | `Init` | `CreateAddressSpace` | scenario construction; no transition event |
| zero-frame preparation | `PrepareZero` | `Prepare` | `PrepareZero` |
| crash fallback and replacement | `Crash`, `KernelFallback`, `Ready`, `Rebind`, `Adopt` | same, with `FallbackPick` | `Crash`, `Fallback`, `RecoverySnapshot`, `Ready`, `Rebind`, `RecoverNext`, `Adopt` |
| mapping publication and success | `Commit`, `Complete`, `SatisfyMapped` | same | `Commit`, `Complete`; `SatisfyMapped` not exercised |
| mapping-policy generation | `AddressSpaceChange` | `AdvanceAddressSpaceGeneration` | not exercised |
| expired uncommitted batch closes authority | `TimeoutRevoke` | `RevokeBegin` | `RevokeBegin` |
| closing-fault cleanup | `Abort` | `Abort` or scope-index `RevokeStep` | `Abort` |
| deadline and closure completion | `DeadlineCancel`, `DeadlineComplete`, `RevokeComplete` | early cancel may be fused; `DeadlineComplete`, `RevokeComplete` | only timeout `RevokeComplete` exercised |

`RecoverySnapshot` and `RecoverNext` are OSTD handshake/probe events, not new
normative fault states or TLA+ linearization points. Stage 4 permits these
explicitly documented backend names while requiring the semantic mapping above.
Stage 5 likewise documents its tombstone, reset, invalidation, and closure
mapping in the I/O spec, Rust oracle, and implementation receipt.

The personality refinement uses the same rule:

| Concept | `PersonalityCser.tla` | Rust personality oracle | OSTD Stage 6A spike |
| --- | --- | --- | --- |
| syscall registration | `Capture` | `Capture` | `Capture` |
| reply preparation | `PrepareReply` | `PrepareReply` | `Prepare`; `PrepareExit` for `exit_group` |
| external write publication | `BackendCommit` | `BackendCommit` | `BackendCommit` |
| write return | `ReplyAccept` | `Reply` | `Reply` |
| process termination | `ReplyAccept` | `Reply` | `PrepareExit`, then terminal `Commit kind=exit_group`; never a backend-output commit |
| crash recovery | `Crash`, `FallbackPick`, `Snapshot`, `Ready`, `Rebind`, `Adopt` | `Crash`, `FallbackPick`, `RecoverySnapshot`, `Ready`, `Rebind`, `Adopt` | `Crash`, `Fallback`, `RecoverySnapshot`, `Ready`, `Rebind`, `RecoverNext`, `Adopt` |
| authority closure | `RevokeBegin`, `KernelClosure`, `RevokeComplete` | `RevokeBegin`, `RevokeNext`, `RevokeComplete` | companion scopes 31/32: `RevokeBegin`, early `NotQuiescent`, user commit/reply rejection, `ClosureNext` abort/drain with real wake, then `RevokeComplete` |

`RecoverySnapshot` and `RecoverNext` remain handshake names, not additional
normative continuation phases. Although the abstract refinement permits a
documented atomic exit prepare+reply macro-step, the current spike keeps those
events separate. No implementation may collapse `BackendCommit` into guest
reply. User-originated invalid or stale
portal operations must refine model rejection to a failure-atomic error; a
kernel panic is not an allowed rejection trace.

Successful transition events carry, where applicable, `seq`, `scope`, `effect`,
`authority_epoch`, `binding_epoch`, transition endpoints, and outcome. Backend
events add fault, task, mapping, queue, device, DMA, reset, invalidation, and
tombstone identities as appropriate.

Injection points are part of the architecture rather than test-only accidents.
They are required immediately before and after every linearization point and at
every asynchronous acknowledgement boundary. Tests must be able to delay,
duplicate, replay, drop, or crash the responsible service without bypassing the
normal kernel path.

## Engineering and verification boundary

The repository has one public host interface: `./x`. It owns Docker image
selection, host/guest backend ordering, locks, freshness boundaries, and the
stable `doctor/build/test/run/verify/clean` contract. It does not implement
CSER transitions or inline semantic oracles.

The implementation layers below that front door are intentionally separate:

- `tools/xtask/` runs the pinned in-container Rust, catalog, scenario, and TLA+
  workflows;
- `kernel/nexus-ostd/x` privately owns the cargo-osdk kernel/personality image,
  generated runner snapshot, and primary QEMU receipt;
- both OSTD build graphs verify and consume the same canonical OSTD overlay;
  `experiments/ostd-virtio-cser-spike/x` privately owns the VirtIO/IOMMU image
  and split serial/debug receipt;
- `tools/workflow/system-composition.sh` consumes those two independently
  ordered evidence domains and owns their positive and negative consistency
  checks.

The formal kernel prototype is physically partitioned into `cser/`, `domains/`,
`personality/`, and `probes/`. The safe-Rust reference model stays in a separate
root workspace and does not share transition implementations with the kernel.
This is an evidence boundary, not merely a Cargo-layout preference.

A full verify first removes every expected old artifact and creates a JSON
start record containing the real invocation, Git revision, dirty state, a
path/content/executable-mode fingerprint of every tracked or nonignored
untracked source, the cold-rebuild request, and a per-run nonce. The final
manifest generator requires two ordered completion receipts: the in-container
reference-model/specification gate seals its artifact set only after both parts
succeed, and the root workflow seals the complete artifact set only after both
QEMU backends and the composition oracle succeed. Each receipt binds the start
nonce, source snapshot, invocation, rebuild state, predecessor receipt, and
exact artifact digests. The generator then recomputes the source snapshot and
accepts only nonempty specification, QEMU, and composition artifacts created
after the start record whose required success markers are present, whose
metadata stays stable while read, and whose digests still match both receipts.
Consequently, focused commands after a failed full run cannot splice together a
successful manifest. A fresh 256-bit orchestration token exists only in the root
`verify` process, is passed only to the start, final-sealing, and
manifest-publication steps, and is persisted solely as a hash bound into the
nonce; a later process therefore cannot seal or publish an abandoned run. The
published manifest records the same run identity, honest research limits,
completion-receipt digest, and SHA-256 of every accepted artifact in
`target/verification/manifest.json`.

This token/receipt chain is a trusted-workspace consistency boundary: it closes
accidental or interrupted cross-command evidence reuse through the public
workflow. It is not authentication against an actor who can rewrite ignored
evidence files and invoke private tooling with arbitrary environments. The
release trust anchor remains the exact Git revision and its isolated remote CI
run.

One repository-wide host lock covers public build, format, check, run, clean,
and composition commands. Manifest publication is an internal final step of the
same token-holding full-verify process rather than a standalone command. Direct kernel and VirtIO backend
invocations take the same lock, and backend-local locks protect their artifact
sets. Composition takes both backend locks in a fixed kernel-before-VirtIO
order. Therefore a full verify and its manifest observe one immutable evidence
set rather than logs truncated or replaced by a concurrent maintenance run.
CI uploads the same manifest on success and the raw bounded evidence on
failure.

### Stage 7B bounded evaluation boundary

Stage 7B is accepted only at the following exact concurrency boundary:

> production transition source under a Loom-modeled outer mutex

Fourteen race rows map live transition sources to Loom harnesses at that outer
mutex. This is not checking of the OSTD `SpinLock`, interrupt masking, SMP
execution, lock freedom, production liveness, or production scheduling
fairness. The release evaluator separately runs with one vCPU and single-thread
TCG. Its twenty fault cells are case-local: fifteen cells use independent,
nonzero-credit `EffectRegistry` ledgers and five scheduler cells carry typed
`NoCredit` witnesses. They do not form one shared production fault-budget scope,
and they do not establish cross-object crash/panic atomicity between a
transition gate and a separate Registry ledger.

The fourteen scale points are exact structural tuples, not an asymptotic or
production `O(k)` result. The twenty-nine performance cases retain raw
guest-visible-TSC samples and recomputed descriptive statistics, but have no
threshold, comparative baseline, hardware-cycle, or low-overhead claim. The
released `v0.1.0` sixteen-row primary-source matrix contains fourteen full-text
audits and two primary-metadata-only rows. The current-main follow-up contains
fifteen full-text audits and one primary-metadata-only row, Atomic RPC. The
resulting contribution verdict remains `narrow`; novelty, firstness, and proof
remain unestablished.

The bounded checkpoint is release evidence only when a clean cold
`NEXUS_REBUILD=1 ./x verify` and GitHub CI for the exact pushed revision both
pass. The manifest and ordered start/model/complete receipts bind the Stage 7B
JSON/log artifacts into the same source fingerprint, nonce, and artifact hash
set as the formal and QEMU evidence. That acceptance does not widen the frozen
five-domain predecessor, identify the separate Stage 5B device effect with the
seven-domain cohort, or establish a production multi-service authority
transport.

## Verification and evaluation matrix

| Property or boundary | Current evidence | Required next evidence |
| --- | --- | --- |
| Core register/commit/revoke/crash/rebind semantics | twelve bounded TLC model families, including the frozen five-domain composition and additive seven-domain Linux I/O successor; corresponding Rust reference oracles; pager, I/O, both composition models, runtime-filesystem, and runtime-network Loom gates | production-lock/SMP refinement and differential mixed-service traces |
| Post-revoke commit exclusion | all domain refinements plus the composition finite model/Rust/Loom gates; the bounded OSTD composition gate rejects stale child and commit operations after root revoke | production-lock/SMP races, asynchronous mixed-service injection, and same-boot device publication |
| Single terminalization | all twelve finite families and Rust oracles; pager, I/O, both composition successors, runtime-filesystem, and runtime-network Loom gates; Stage 7B checks fourteen production transition-source race rows under a Loom-modeled outer mutex, with internal-nonce OneShot receipt provenance; bounded QEMU receipts consume each continuation/publication/closure receipt once | OSTD `SpinLock`/interrupt/SMP refinement, production-lock races, and asynchronous device completion injection |
| Budget conservation | baseline/pager scalars; Stage 5 typed I/O; Stage 6B typed credits; the five-domain predecessor returns five credits, while the seven-domain successor returns nine units in eight classes and retains the timed-out DMA credit until retry; Stage 7B checks fifteen case-local nonzero-credit Registry ledgers plus five typed `NoCredit` scheduler witnesses | production multi-resource accounting and leak/duplication tests under concurrency and repeated device failure; one shared production fault scope and cross-object crash/panic atomicity remain unestablished |
| Scheduler fallback | weak-fair TLA+ property; one-CPU QEMU selects the FIFO task on the first post-crash fallback selection attempt; the Stage 7B release evaluator checks five case-local typed-`NoCredit` scheduler cells tied to real fallback picks, including lease-expiry and repeated-crash cases; raw ticks remain artifact diagnostics | shared production fault scope, SMP/production-lock races, overload, and production liveness |
| Pager one-shot reply and crash/rebind | pager TLC refinement: 17,150 generated / 7,528 distinct / reported depth 17-18 across parallel clean runs / 10 temporal branches; Rust: 12 deterministic + 5 proptests (64 cases each); one-CPU QEMU `recover` + `timeout` observations | real one-shot handle/portal, serialized recovery state, full response-boundary injection, multi-client and SMP refinement |
| Pager QuiescentClosure | Loom three-stage surrogate; QEMU three-phase Closing -> lock-free frame/waker cleanup -> credit return and RevokeComplete; reusable OSTD Waker fenced by Nexus state | production-lock/SMP interleavings, allocation failure and arbitrary task-termination paths |
| Personality QuiescentClosure | Personality TLA+/Rust closure accounting; companion QEMU scopes observe early completion rejection, scope-local abort/drain, real waker take/publication/drop, empty live index, and final completion | scope-30 and cross-service closure, stuck backend timeout/tombstone, production-lock/SMP interleavings |
| Futex wait/wake/requeue crash/rebind | Stage 6B.1 predecessor plus Stage 6B.2 requeue semantics and adapted Round 4 complete / Checked and Observed: requeue TLC 4,786,581 / 1,927,174 safety states and 247,047 / 140,473 action states; common-registry/requeue Rust tests; one-CPU QEMU observes shared-`VmSpace` clone/mmap/thread exit, atomic A-to-B move, affected count 2, explicit adoption, stale rejection, both closure orders, and full credit/index return | Linux timeout, shared/PI/robust futexes, unmap invalidation, lost-wakeup/SMP, and production-registry refinement |
| Readiness and epoll | readiness TLC checks atomic sample-and-arm, LT/ET/ONESHOT, current-binding subscription fencing, ready/timeout/revoke winner and closure; Rust has 7 tests; QEMU lifecycle recovers six effects, while adapted Round 5 executes 23 pipe/socketpair/regular-file-`EPERM` syscalls | production fd table/epoll ABI, asynchronous source injection, filesystem/network producers, SMP locking and lost-wakeup proof |
| Failure-atomic exec and dynamic PIE | exec TLC checks invisible staging, ready-proof invalidation, and one whole-image commit; Rust has 7 tests; QEMU performs real launcher `execve`, eleven-effect crash/rebind/adopt, one `VmSpace` publication, auxv plus two TLS images, explicit FS-base load/save, exact output and closure | general relocations/shared libraries/libc, filesystem-backed loading, multi-task TLS lifecycle, SMP and production task-context ownership |
| DMA quiescence | Stage 5A one-owner negative/ownership receipt plus Stage 5B real readonly device DMA, status-zero reset, and request + two queue owners released after queued IOTLB completion on pinned QEMU | physical-device drain contracts, IRQ quiescence, per-device domains, multi-page and SMP tests |
| I/O tombstone/timeout | TLA+/Rust timeout/retry semantics plus Stage 5B fail-closed session/IOTLB ownership retention and successful retry; timeout explicitly software-injected | real-time deadline source, durable recovery worker, repeated failure, device-loss and hardware-timeout tests |
| Work proportionality | the target-local futex oracle closes `k=6` while leaving unrelated `N=96` unchanged; the Stage 7B release evaluator adds fourteen exact structural tuples spanning fixed-`N`/varying-`k`, fixed-`k`/varying-`N`, and retained-history variation, with target/index work following the checked cohort and unrelated/history visits remaining zero | production-lock/SMP timing curves and broader tuples; the finite structural observations do not establish an asymptotic or production `O(k)` claim |
| Cross-service composition | The frozen `CompositionCser` predecessor and additive `LinuxIoCompositionCser` successor have separate formal, safe-Rust/Loom, OSTD, and strict-oracle evidence. The successor uses a fresh seven-domain/nine-effect root cohort and prior same-boot filesystem/network receipts; Stage 5B remains non-identity component consistency. Stage 7B adds twenty bounded case-local fault cells, not one shared cross-service production ledger | identity-preserving or same-boot device integration; unbounded graphs, production portals/locks, SMP, and an integrated parameterized fault matrix over a shared production scope with cross-object crash/panic atomicity |
| Runtime filesystem | `RuntimeFsCser` safety/action graphs, 15 safe-Rust/property/Loom gates, unchanged retained ELF artifact gate, and exact 14-syscall OSTD execution; the later one-vCPU same-boot slice observes one real fsd-v1 page-fault crash after filesystem Prepare, fresh-task/fresh-`VmSpace` fsd-v2 recovery and explicit adoption, failure-atomic stale Prepare rejection, the exact six-effect production Registry cohort, normal real VirtIO/IOMMU DMA, a revoke-wins pre-commit lane, leaf-first closure, and one guest wake/reply | the post-device-commit/pre-reply service-crash point and every remaining frozen fault cell, a real IRQ path, 2/4-vCPU and multi-client execution, general VFS/persistence, durable external effects, and full production-adapter equivalence |
| Runtime network | `RuntimeNetCser` safety/action graphs (3,698,288 / 720,002 depth 42 and 28,449 / 14,328 depth 35), eight witnesses, 10 + 2 + 4 safe-Rust gates, unchanged 22-syscall retained ELF, bounded in-memory loopback, real `UserMode` netd-v1 page fault/netd-v2 rebind-adopt, kernel-owned readiness, four typed credits, and positive/negative trace/artifact oracles | smoltcp or real TCP breadth, external packets, VirtIO-net/NIC, multi-connection/backpressure behavior, SMP and production portal/lock refinement |
| Linux pressure | Bounded Stage 6 Checked/Observed: all six fixed core inputs (`linux-hello`, adapted Round 4, adapted Round 5, dynamic PIE, runtime filesystem, runtime network), strict positive/negative oracles, bounded recovery companions, and additive seven-domain composition evidence | integrated mixed-service workload matrix; general ABI/VFS/TCP/device/SMP breadth |
| Stage 7B evaluation and contribution decision | concurrency boundary exactly `production transition source under a Loom-modeled outer mutex`, with fourteen mapped races Checked; twenty case-local fault cells and fourteen finite structural scale tuples Checked in release single-vCPU QEMU; twenty-nine raw guest-visible-TSC cases Observed without thresholds or a comparative baseline; released `v0.1.0` prior-art boundary 14/2 and current-main follow-up 15/1; the recorded implementation checkpoint has cold/CI acceptance; verdict `narrow` | repeat exact-revision cold/CI acceptance for each later release; full-text resolution of the remaining Atomic RPC row; production-lock/SMP, hardware-cycle, durable-external-effect, shared-production-fault, cross-object crash/panic atomicity, and broader Linux evidence before any stronger contribution claim |

TLC's current result is a complete graph only for its committed finite
configuration. QEMU results are concrete observations only for their pinned
software and machine configuration. Evaluation reports must preserve those
qualifiers.

## Repository direction

The current semantic artifacts are:

- `specs/cser/` — baseline, pager, I/O, personality, private-futex, two-key
  requeue, readiness, exec, runtime-filesystem, runtime-network, frozen
  five-domain composition, and additive seven-domain Linux I/O PlusCal/TLA+
  protocols and bounded TLC
  configurations;
- `crates/cser-model/` — safe-Rust executable core, pager, I/O, personality,
  personality-local successors, and both composition reference models;
- `kernel/nexus-ostd/` — maintained, pinned OSTD kernel prototype with physical
  CSER/domain/personality/probe ownership boundaries plus bounded
  `linux-hello`, futex, epoll/readiness, dynamic PIE, runtime-filesystem,
  runtime-network, frozen five-domain composition, and additive seven-domain
  Linux I/O receipts;
- `experiments/ostd-virtio-cser-spike/` — pinned patched-OSTD mediated VirtIO,
  reset tombstone and three-owner queued-IOTLB-completion experiment.

Legacy kernel, Starnix-like, conformance, and performance modules are not
automatically part of this architecture. `REWORK.md` classifies each as retain,
migrate, rewrite, or delete. Git history provides archival access; the live tree
should contain only an active implementation or evidence that still constrains
the research.

The developer interface is a Docker-pinned environment orchestrated by one root
`./x` and Rust `xtask`. Nix and Just were removed after every retained gate
moved to that entry point. CI uses the same command surface, adds a parallel
quick-feedback gate, and retains the complete `./x verify` as the acceptance
authority.

## Open architecture decisions

The following are intentionally unresolved:

- the exact representation and derivation rules for nested scopes;
- whether one effect may depend on multiple scopes and, if so, which revoke
  semantics avoid deadlock or hidden global scans;
- the SMP locking/atomic scheme for commit and epoch publication;
- the production pager reply-handle representation, recovery-state format,
  multi-client policy, and SMP address-space/TLB protocol;
- whether the canonical downstream OSTD DMA/GSI overlay is upstreamed, when the
  primary runtime adopts it, and how its single-page/single-generation form
  becomes a production domain/SMP API;
- queue-level versus device-level reset granularity for each VirtIO transport;
- the tombstone retry, administrative recovery, and resource-pressure policy;
- treatment of durable external effects that require idempotency or
  application-level compensation rather than local drain;
- whether the completed fixed six-workload Linux core gate should be extended
  beyond its bounded evidence before broader compatibility evaluation.

Each decision must be resolved first in the smallest relevant model and spike.
An unresolved item is not permission to assume the strongest behavior in code
or in a research claim.
