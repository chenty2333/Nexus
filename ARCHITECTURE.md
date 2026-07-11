# Nexus architecture

Status: architecture contract for the CSER prototype, July 2026.

This document separates the intended architecture from what the repository has
already demonstrated. The evidence terms **Specified**, **Checked**,
**Observed**, **Planned**, and **Candidate contribution** have the meanings in
`VISION.md`.

For operations covered by the current model, `specs/cser/Cser.tla` is the
semantic source of truth and `crates/cser-model` is its executable oracle. A
future implementation must refine those operations or change the model first;
it must not silently redefine their linearization points. Sections marked
planned extend beyond the current finite model.

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

Status: **Planned**.

### One-shot fault continuation

When a user thread faults, the kernel suspends it and registers a continuation:

```text
FaultContinuation {
    effect_token
    faulting_thread
    address_and_access
    address_space_generation
    state: Pending | Resolved | Aborted
}
```

The security representation is a one-shot reply authority. A resolve operation
must atomically validate the token and proposed mapping, install the mapping,
consume the continuation, and make the thread eligible to resume. The precise
PTE/TLB publication step will be the pager effect's concrete `Commit` and must
be specified before implementation.

Required behavior:

- resolve or abort consumes the continuation exactly once;
- a token cannot reply to another thread, address space, or fault generation;
- a stale pager binding cannot resolve a fault after crash;
- a replacement cannot reply before ready/rebind;
- each eligible old, uncommitted continuation requires explicit adoption;
- timeout or unrecoverable policy failure aborts deterministically, for example
  by delivering a fault outcome or terminating the affected task, rather than
  leaving it suspended forever;
- revoke and resolve races obey the same commit gate as the abstract effect.

Before this slice passes its gate, the TLA+/Rust models must be extended with
the chosen continuation states, and QEMU injection must cover crash before
delivery, after delivery, around adoption, immediately before mapping commit,
and after commit but before reply acknowledgement.

The kernel fallback for pager loss is intentionally not a second general pager.
Its minimum obligation is bounded, safe terminalization. Any zero-fill or
emergency mapping behavior would be an explicit policy decision and is not
currently assumed.

## Vertical slice 3: mediated VirtIO and DMA closure

Status: **Planned and blocked on the DMA ownership gate**.

The service may construct and schedule an I/O request, but a Nexus-owned portal
must validate its effect token, descriptors, budgets, pinned buffers, device,
and queue before publication.

The provisional request phases are:

```text
registered -> descriptors prepared -> queue published -> device-owned
       |               |                    |
       +---- cancel ---+                    +-> complete or drain/reset
```

For a split VirtIO queue, publication to the available ring and the point at
which the device is notified are distinct machine operations. The concrete
`Commit` must be defined per transport so that revocation cannot race through a
gap between an epoch check, ring visibility, and notification. The design may
choose a conservative earlier commit point; it may not claim cancellation once
the device can observe the request.

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

Before the I/O slice proceeds, Nexus must select and audit exactly one option:

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
- wrappers around `Waiter`/`Waker` and `Jiffies` that retain an effect token.

These mechanisms should be reused behind Nexus adapters. CSER state should not
be patched into OSTD internals merely for convenience.

### Not accepted yet

- synchronous DMA unmap plus completed IOTLB invalidation;
- SMP scheduler protocol and cross-CPU epoch publication;
- pager continuation ownership and address-space generation fencing;
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

The current TLA+ protocol names these ordered transition actions:

```text
Register Prepare Commit Complete RevokeBegin RevokeStep RevokeComplete
Crash FallbackPick Rebind Adopt
```

The Rust reference model adds `CreateScope` as an executable initialization
event. Scope creation is part of TLA+ `Init`, not a checked TLA+ transition, so
`CreateScope` must not be described as an action checked by the current TLC
graph. The OSTD spike emits only the subset it exercises and also records
rejection outcomes such as stale or no-supervisor proposals.

This difference is explicit rather than papered over as one already-unified
vocabulary. Before a new kernel slice depends on scope creation/derivation,
timeout, tombstone, reset, or other lifecycle events, those actions and fields
must be normalized in the spec, Rust oracle, and implementation trace.

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
| Core register/commit/revoke/crash/rebind semantics | bounded TLC graph; Rust reference model | concurrency refinement and differential kernel traces |
| Post-revoke commit exclusion | checked in current finite model | Loom/Kani race harnesses and system injection around commit |
| Single terminalization | checked in finite model; Rust tests | duplicate/stale pager and device completion injection |
| Scalar budget conservation | checked in finite model; Rust model | typed budget implementation and leak/duplication tests |
| Scheduler fallback | weak-fair TLA+ property; one-CPU QEMU fallback observed in one tick | lease-expiry path, SMP races, overload and repeated-crash tests |
| Pager one-shot reply | none | extended spec/model, QEMU resolve/abort/rebind matrix |
| DMA quiescence | fail-closed negative OSTD probe | one-owner synchronous invalidation path and real device tests |
| Tombstone/timeout | none | protocol extension, retained-resource tests, eventual retry/reset |
| Work proportionality | per-scope Rust data structure | fixed-`N` varying-`k` and fixed-`k` varying-`N` kernel curves |
| Cross-service composition | none | scheduler + pager + I/O crash matrix under mixed workloads |
| Linux pressure | retained legacy workload inputs only; not evidence for new architecture | bounded personality workloads on the completed CSER slices |

TLC's current result is a complete graph only for its committed finite
configuration. QEMU results are concrete observations only for their pinned
software and machine configuration. Evaluation reports must preserve those
qualifiers.

## Repository direction

The current semantic artifacts are:

- `specs/cser/` — current PlusCal/TLA+ protocol and bounded TLC configuration;
- `crates/cser-model/` — safe-Rust executable reference model;
- `experiments/ostd-cser-spike/` — pinned OSTD scheduler/API/IOMMU experiment.

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
- the pager mapping commit point and minimal abort/fallback policy;
- the single owner and public contract for IOMMU invalidation;
- queue-level versus device-level reset granularity for each VirtIO transport;
- the tombstone retry, administrative recovery, and resource-pressure policy;
- treatment of durable external effects that require idempotency or
  application-level compensation rather than local drain;
- the exact bounded Linux compatibility workload used for final pressure tests.

Each decision must be resolved first in the smallest relevant model and spike.
An unresolved item is not permission to assume the strongest behavior in code
or in a research claim.
