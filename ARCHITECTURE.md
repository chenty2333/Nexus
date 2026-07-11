# Nexus architecture

Status: architecture contract for the CSER prototype, July 2026.

This document separates the intended architecture from what the repository has
already demonstrated. The evidence terms **Specified**, **Checked**,
**Observed**, **Planned**, and **Candidate contribution** have the meanings in
`VISION.md`.

For baseline operations, `specs/cser/Cser.tla` is the semantic source of truth;
`specs/cser/PagerCser.tla` is the explicit pager successor refinement.
`crates/cser-model` provides the corresponding executable oracles. A future
implementation must refine those operations or change the relevant model first;
it must not silently redefine their linearization points. Sections marked
planned extend beyond the current finite models.

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
references, not trusted integer structs. The simple Rust and OSTD spike structs
are executable protocol probes, not the final security representation.

The binding epoch is checked at service-originated `Prepare`, `Commit`, reply,
and adoption boundaries. Kernel-owned cleanup may continue after the binding is
fenced; otherwise a crashed service could prevent its own revocation.

### Budget ledger

The current model uses one scalar consumable credit:

```text
free + held + spent = total
```

The implementation will require typed ledgers for resources such as CPU time,
pinned frames, DMA mappings, queue slots, bytes, and outstanding continuations.
Registration transfers credit into `held`; commit accounts it as `spent` or
backend-owned; abort returns renewable credit; a tombstone retains credit until
safe cleanup. Replenishment and typed exchange are planned refinements and must
preserve no-duplication.

### Tombstone (planned)

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
being reused. Tombstones and real time are not in the current TLA+ model; they
must be added to the protocol before the mediated I/O slice claims
`QuiescentClosure`.

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

The Rust reference model exercises the per-scope index structurally. No
kernel-scale `k`/`N` performance curve has yet been measured.

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
`Prepare`; selecting the proposed runnable task is the scheduling effect's
`Commit`.

The observed path is:

```text
UserMode syscall -> proposal -> Commit selected task
UserMode page fault -> policy Crash -> binding epoch 1 -> 2
kernel FIFO fallback -> FallbackPick within one tick of Crash (0-1 observed)
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

Limitations:

- there is one run queue and one CPU;
- the measured crash fallback bound is one tick in this test configuration, not
  a general real-time guarantee;
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
  states, 7,528 distinct states, zero queued states, depth 17, and ten checked
  temporal-property branches.
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

Status: **Planned; NO-GO while the DMA ownership gate remains open**.

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

Status: **Observed negative result**.

OSTD 0.18 removes DMA mappings without exposing a public synchronous IOTLB
invalidation-and-completion operation. Its invalidation/domain state is
crate-private, so an external Nexus adapter cannot safely become a second VT-d
owner. The current adapter therefore returns
`IotlbInvalidationUnavailable` and never fabricates `Quiesced`.

Before a real DMA-closure implementation proceeds or reports `Quiesced`, Nexus
must select and audit exactly one option:

1. upstream a public synchronous unmap/invalidate/wait API to OSTD;
2. carry a small, isolated, reviewed OSTD patch implementing that contract; or
3. move IOMMU/DMA ownership out of OSTD into one Nexus-owned layer.

This decision must include queue/domain ownership, invalidation completion,
device reset ordering, frame lifetime, and an executable failure test. Merely
calling an unmap function is insufficient.

## Linux personality

Status: **Planned last-stage pressure test**.

The Linux personality is a user-space compatibility service. It may implement
Linux syscall dispatch, process/thread semantics, memory mappings, file
descriptors, pipes, epoll, signals, filesystems, sockets, ELF/auxv integration,
and namespaces by composing Nexus services. Linux UAPI definitions and libc are
reused rather than handwritten.

It is intentionally integrated after scheduler, pager, and I/O effect semantics
are independently testable. Its purpose is to create mixed real workloads—such
as a page fault plus timer plus epoll wait plus socket or file I/O—and then crash
or replace services underneath them. Initial compatibility targets must be
bounded, for example static musl programs, selected libc tests, a small shell
tool set, and focused LTP/kselftest or network workloads. “Runs Linux software”
is not the Nexus research claim.

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
  closure ordering documented above.

These mechanisms should be reused behind Nexus adapters. CSER state should not
be patched into OSTD internals merely for convenience.

### Not accepted yet

- synchronous DMA unmap plus completed IOTLB invalidation;
- SMP scheduler protocol and cross-CPU epoch publication;
- a production one-shot continuation handle, real recovery snapshot payload,
  multi-client address-space mutation fencing, and SMP TLB shootdown;
- device drain/reset and interrupt quiescence;
- an end-to-end nested authority scope implementation.

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
graph. The OSTD spike emits only the subset it exercises and also records
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
Before Stage 5 depends on tombstone, reset, invalidation, or other new lifecycle
events, their fields and refinement mapping must likewise be established in the
spec, Rust oracle, and implementation trace.

Successful transition events carry, where applicable, `seq`, `scope`, `effect`,
`authority_epoch`, `binding_epoch`, transition endpoints, and outcome. Backend
events add fault, task, mapping, queue, device, DMA, reset, invalidation, and
tombstone identities as appropriate.

Injection points are part of the architecture rather than test-only accidents.
They are required immediately before and after every linearization point and at
every asynchronous acknowledgement boundary. Tests must be able to delay,
duplicate, replay, drop, or crash the responsible service without bypassing the
normal kernel path.

## Verification and evaluation matrix

| Property or boundary | Current evidence | Required next evidence |
| --- | --- | --- |
| Core register/commit/revoke/crash/rebind semantics | bounded TLC graph; Rust reference model; four pager Loom gate refinements | implementation-specific concurrency refinement and differential kernel traces |
| Post-revoke commit exclusion | baseline and pager finite models; pager Rust tests; Loom commit/timeout gate; QEMU timeout forbids commit/resume after `RevokeBegin` | real portal replay, SMP and production-lock races, and device publication injection |
| Single terminalization | baseline and pager models; pager Rust tests; Loom stale/duplicate-reply and wake-authority gates; QEMU `recover` and `timeout` each terminalize once | delayed/duplicate real portal replies, SMP and production-lock races, and device completion injection |
| Scalar budget conservation | baseline and pager models; QEMU timeout keeps credit `Held` through lock-free frame/waker cleanup and returns it only before `RevokeComplete` | typed multi-resource implementation and leak/duplication tests under concurrency and device failure |
| Scheduler fallback | weak-fair TLA+ property; one-CPU QEMU fallback observed in one tick | lease-expiry path, SMP races, overload and repeated-crash tests |
| Pager one-shot reply and crash/rebind | pager TLC refinement: 17,150 generated / 7,528 distinct / depth 17 / 10 temporal branches; Rust: 12 deterministic + 5 proptests (64 cases each); one-CPU QEMU `recover` + `timeout` observations | real one-shot handle/portal, serialized recovery state, full response-boundary injection, multi-client and SMP refinement |
| Pager QuiescentClosure | Loom three-stage surrogate; QEMU three-phase Closing -> lock-free frame/waker cleanup -> credit return and RevokeComplete; reusable OSTD Waker fenced by Nexus state | production-lock/SMP interleavings, allocation failure and arbitrary task-termination paths |
| DMA quiescence | fail-closed negative OSTD probe | one-owner synchronous invalidation path and real device tests |
| I/O tombstone/timeout | none | protocol extension, retained-resource tests, eventual retry/reset |
| Work proportionality | per-scope Rust data structure | fixed-`N` varying-`k` and fixed-`k` varying-`N` kernel curves |
| Cross-service composition | scheduler fallback and pager are co-resident but deliberately independent; no shared-scope cross-service evidence | scheduler + pager + I/O crash matrix under mixed workloads |
| Linux pressure | retained legacy workload inputs only; not evidence for new architecture | bounded personality workloads on the completed CSER slices |

TLC's current result is a complete graph only for its committed finite
configuration. QEMU results are concrete observations only for their pinned
software and machine configuration. Evaluation reports must preserve those
qualifiers.

## Repository direction

The current semantic artifacts are:

- `specs/cser/` — current PlusCal/TLA+ protocol and bounded TLC configuration;
- `crates/cser-model/` — safe-Rust executable reference model;
- `experiments/ostd-cser-spike/` — pinned OSTD scheduler/pager/API/IOMMU
  experiment.

Legacy kernel, Starnix-like, conformance, and performance modules are not
automatically part of this architecture. `REWORK.md` classifies each as retain,
migrate, rewrite, or delete. Git history provides archival access; the live tree
should contain only an active implementation or evidence that still constrains
the research.

The intended developer interface is a Docker-pinned environment orchestrated by
one root `./x` and Rust `xtask`. Nix and Just were removed after every retained
gate moved to that entry point. CI and local verification call the same
commands.

## Open architecture decisions

The following are intentionally unresolved:

- the exact representation and derivation rules for nested scopes;
- whether one effect may depend on multiple scopes and, if so, which revoke
  semantics avoid deadlock or hidden global scans;
- the SMP locking/atomic scheme for commit and epoch publication;
- the production pager reply-handle representation, recovery-state format,
  multi-client policy, and SMP address-space/TLB protocol;
- the single owner and public contract for IOMMU invalidation;
- queue-level versus device-level reset granularity for each VirtIO transport;
- the tombstone retry, administrative recovery, and resource-pressure policy;
- treatment of durable external effects that require idempotency or
  application-level compensation rather than local drain;
- the exact bounded Linux compatibility workload used for final pressure tests.

Each decision must be resolved first in the smallest relevant model and spike.
An unresolved item is not permission to assume the strongest behavior in code
or in a research claim.
