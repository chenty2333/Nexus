# RFC 0003: closing causal coverage for the production filesystem slice

- Status: **Draft / prospective implementation contract**
- Target: RFC 0001 Phase 2 through Phase 4 refinement work
- Supersedes: nothing
- Changes accepted `v0.1.0` claims: **no**
- Changes RFC 0001 or RFC 0002 acceptance: **no**

## Claim discipline

This RFC records a design derived from a read-only audit of the bounded
same-boot filesystem slice. It is not an implementation report, runtime
observation, evidence receipt, accepted phase, or release claim.

The machine-readable inventory in
`evaluation/production-identity/causal-coverage.toml` currently records twenty
reviewed boundaries: six tracked effects, six root-owned publications, and
eight uncovered gaps. That inventory is an audited declaration. Its validator
does not discover undeclared source or runtime boundaries, and its existence
does not prove causal coverage.

This RFC groups the eight gaps into seven prospective implementation tranches.
The guest waiter and guest waker become one continuation obligation because
they represent the two sides of one request-derived suspension. None of the
eight audited gaps is reclassified by this document.

The words **must**, **ticket**, **receipt**, **credit**, **failure atomic**, and
**production path** below state requirements for later work. They do not report
that the current source satisfies those requirements. Production path retains
the narrow definition in RFC 0001: the normal Nexus/OSTD path used by the
workload, not an evaluation-only state machine or test adapter.

## Objective

For the first executable `pread64` workload, every request-derived operation
that can outlive its initiating stack frame, cross a service or device boundary,
publish to another actor, retain a resource, or require retry must be either:

1. represented under the same root in the authoritative production
   `EffectRegistry`; or
2. classified as reviewed kernel TCB infrastructure with a reason that does not
   hide request-specific authority, ownership, or publication.

The objective is causal closure, not the conversion of every kernel instruction
into an effect. Generic execution machinery may remain in the TCB. A
request-specific decision carried by that machinery may not disappear from the
root merely because its lowest-level implementation is generic.

## TCB boundary

The following low-level mechanisms may remain kernel TCB infrastructure:

- generic OSTD task allocation, runnable-queue insertion, context switching,
  and scheduler bookkeeping;
- raw x86 exception entry, page-fault vector delivery, and decoding of CR2 and
  the architecture error code;
- raw OSTD park, unpark, and the documented Release/Acquire edge between them;
- raw timer interrupt delivery and the monotonic clock or callback counter that
  it advances; and
- low-level allocator, DMA allocator, IOMMU command, and invalidation
  implementation.

That classification does not cover the following request-derived policy:

- whether a guest or service task may execute for this root;
- which service fault terminates which task lease and binding;
- admission, claim, drain, or cancellation of a filesystem request or delayed
  service command;
- reservation of queue, pinned-frame, and DMA-mapping ownership;
- which blocked guest continuation may be resumed, by which binding and
  generation;
- the deadline generation, retry policy, timeout disposition, or retained
  owner; or
- the backend outcome and one-shot guest reply.

Therefore none of the current eight gaps may be closed wholly by relabeling it
as TCB. A later review may refine individual low-level sub-operations, but the
request-specific obligation described here must remain rooted.

## One authoritative obligation model

All seven tranches extend the same authoritative `EffectRegistry`. Source
files may be split by identity, recovery, device, handoff, and projection
concerns, but there must not be a second semantic registry, detached credit
sidecar, reconstructed trace ledger, or evaluation-only authority table.

An implementation may give each obligation a specialized Rust type, but every
type must bind at least:

    ObligationIdentity {
        registry_instance,
        scope_id,
        scope_generation,
        root_effect,
        immutable_parent,
        obligation_id,
        obligation_generation,
        obligation_kind,
        authority_epoch,
        domain_id,
        binding_epoch,
        nonce,
    }

The Registry mints opaque tickets with private fields. Tickets are non-`Copy`
and cannot be constructed from public integers, user-controlled bytes, log
markers, or another Registry's observation. Consumption either returns a typed
successor ticket/receipt or returns the original linear input with a typed
failure where retry is allowed. Identity and counters must reject exhaustion;
they must not wrap or silently reuse a generation.

The common lifecycle is:

    Reserved -> Armed -> Published -> Acknowledged -> Terminal
                  \                         \
                   +------> Retained <-------+

Not every obligation needs every state. It must nevertheless have one
discoverable root-owned disposition. A fallible operation either leaves the
complete semantic projection unchanged or leaves a valid committed obligation
that recovery can query. Retained is an honest terminal-blocking disposition,
not a synonym for success or closure.

The Registry owns reverse indexes needed to find obligations by root, immutable
parent, task instance, domain/binding, resource owner, and retry generation.
Each index membership and credit mutation is installed or removed in the same
failure-atomic transition as the primary record. Normal, revoke, crash,
replacement, and retained-worker paths use those indexes rather than scanning
history.

Credits are typed and conserved. At minimum this RFC introduces or separates:

- device-preparation queue-slot, pinned-page, and DMA-mapping credits;
- task-admission credits;
- service-request and delayed-command credits;
- guest-continuation credits;
- guest-reply credits;
- deadline credits; and
- service-fault-event credits.

An implementation may refine these classes. It may not merge them into an
untyped population count or return them before their external owner is known to
be quiescent.

## Closure order

The implementation order is normative because each later tranche depends on an
earlier authority boundary:

1. queue and DMA preparation;
2. task admission;
3. filesystem service request and delayed-command queues;
4. guest continuation, combining waiter and waker;
5. guest reply;
6. deadline and retry generation; and
7. request-derived page-fault disposition.

A tranche may land behind a disabled capability, but no ledger row leaves
`uncovered-gap` until the normal shared production path uses it and the
required evidence is accepted.

## Queue and DMA preparation

### Contract

Hardware preparation currently precedes enrollment of the corresponding
device-derived cohort. The replacement contract starts under the adopted
filesystem effect:

    reserve_device_preparation(identity, preparation_context)
        -> DevicePreparationTicket

    materialize_device_cohort_from_preparation(
        ticket,
        prepared_hardware_identity,
    )
        -> DeviceCohortReceipt

    cancel_device_preparation_with_apply(ticket, cancel_hardware)
        -> Cancelled | Retained(DevicePreparationTombstone)

`reserve_device_preparation` must run before descriptors are reserved, frames
are pinned, or DMA mappings are installed. It reserves exactly one queue-slot,
three pinned-page, and three DMA-mapping credits for the current bounded
request. It binds the current root, service binding, device, queue, device
generation, operation digest, and a fresh preparation nonce. The descriptor
token is deliberately absent at this point because the queue allocator has not
selected it yet.

After hardware preparation, materialization atomically consumes the preparation
ticket, creates the `BlockRequest` and three immutable DMA-owner descendants,
validates and fixes the returned descriptor token and device-session identity,
transfers the already-held credits to those effects, and installs every reverse
index. It does not release and reacquire substitute credits. A caller cannot
predict or reconstruct a descriptor token to gain preparation authority.

The VirtIO crate remains independent of `EffectRegistry`. The kernel adapter
owns both the opaque Registry ticket and the linear hardware preparation. A
driver error cannot fabricate a Registry receipt.

### Failure windows

The additive causal matrix must inject at least:

- reservation failure before hardware mutation;
- root revoke or service crash after reservation and before preparation;
- hardware preparation failure before materialization;
- crash after hardware preparation and before materialization;
- validation or allocation failure during materialization;
- cancellation failure or uncertain device quiescence;
- duplicate materialization or cancellation; and
- wrong root, binding, device session, queue, descriptor, or generation.

Before hardware mutation, failure returns all reserved credits. After hardware
may have mutated, uncertainty retains the exact ticket, hardware owner, and all
credits for a retryable retained worker. Drop alone is never evidence of
quiescence.

## Task admission

### Contract

Generic scheduler operations stay in the TCB, but root-specific permission to
run is represented by a `TaskWorkLease`:

    reserve_task_work(root, role, binding, task_generation)
        -> TaskWorkLease

    admit_task(lease, exact_task_instance)
        -> AdmittedTaskLease

    finish_or_isolate_task(lease, disposition)
        -> TaskTerminalReceipt

The lease is installed before `Task::run` makes the task runnable. The
Registry maintains a reverse index from the exact OSTD task instance to one live
lease. The guest lease descends from the syscall root. The `fsd-v1` lease is
bound to the current filesystem service claim. A supervisor reserves the
`fsd-v2` replacement lease before that task can issue a recovery portal
operation.

Each reserved or admitted task lease holds one task-admission credit. Task exit,
rejected construction, root revoke, domain crash, replacement timeout, and
typed isolation each select one disposition and return or retain that credit.

### Failure windows

Required injections include failure after lease reservation but before task
construction, after construction but before runnable publication, immediately
after runnable publication, task exit before terminal acknowledgement, root
revoke racing admission, stale binding admission, repeated replacement crash,
and task-generation substitution. A task may run only after its admitted lease
is discoverable. A reaper or supervisor may finish an exited task; it may not
reconstruct the lease from a task ID after the fact.

## Filesystem service queue

### Contract

The causal graph becomes:

    syscall root
        -> service request
            -> filesystem effect
                -> device preparation
                    -> block and DMA cohort

The service request is registered before the local protocol queue becomes
visible:

    reserve_service_request(root, descriptor_digest)
        -> ServiceRequestTicket

    enqueue_service_request_with_apply(ticket, queue_write)
        -> EnqueuedServiceRequest

    claim_service_request(request, service_binding)
        -> FilesystemEffect + ServiceClaim

Claiming the request and creating its filesystem child are one failure-atomic
Registry result. The local queue may store an opaque selector, but it does not
own authority independently of the Registry.

The request initially reserves an empty response-continuation slot so this
tranche does not depend on the later continuation implementation. Before queue
arm is enabled for the production workload, the guest-continuation tranche must
bind that slot to one exact rooted continuation. A request with an empty,
substituted, or already consumed slot cannot be armed.

A delayed `Prepare` command is a separate child obligation with its own
non-`Copy` ticket and command-slot credit. Delivery validates the sender task,
binding epoch, target effect, portal generation, and command digest. A stale
command is terminalized with a typed rejection receipt; it is not merely removed
from an `Option`.

Each queued request holds one service-request credit. Each live delayed command
holds one delayed-command credit. A response continuation holds the separate
continuation credit defined below.

### Failure windows

Required injections include crash after Registry reservation but before the
queue write, after the queue write but before arm, after dequeue but before
claim, between claim validation and filesystem-child publication, after claim
before delayed-command installation, before and after rebind, stale command
delivery, duplicate dequeue/claim/delivery, coordinator exit, and root revoke
with a queued or claimed request. Every window ends in a queryable queued,
claimed, terminal, or retained disposition with conserved credits.

## Guest continuation

### Contract

The current waiter and waker represent one logical suspension and must not
become unrelated effects. The Registry creates one `GuestContinuation` under
the syscall root before the raw OSTD waiter/waker pair is exposed:

    reserve_guest_continuation(root, guest_task, vm_generation)
        -> GuestContinuationTicket

    stage_guest_wake(ticket, source_binding, outcome_digest)
        -> GuestWakeTicket

    acknowledge_guest_wake(wake_ticket)
        -> GuestContinuationReceipt

The continuation holds one guest-continuation credit. Its identity binds the
guest task and VM generation, the source service binding allowed to stage the
wake, and a one-shot nonce.

`stage_guest_wake` commits the wake obligation before the adapter calls raw
OSTD unpark. Raw wake occurs without the Registry lock held and uses the
documented Release/Acquire synchronization. The adapter then acknowledges the
exact staged ticket. A crash after staging can retry the same raw wake; a crash
after raw wake but before acknowledgement discovers the same obligation.
Duplicate raw wake tolerance does not authorize duplicate semantic completion.

### Failure windows

The matrix must cover guest exit before park, revoke before park, service crash
before staging, crash after staging but before raw wake, crash after raw wake
but before acknowledgement, duplicate wake and acknowledgement, stale binding,
wrong task or VM generation, and replacement retry. Exactly one continuation
terminal receipt returns the credit. An abandoned or unverifiably delivered
wake remains retained rather than being inferred complete from scheduler state.

## Guest reply

### Contract

Backend outcome and guest-visible reply are separate boundaries. Device
completion first records an immutable backend outcome in kernel-owned state.
The root then creates a `GuestReply` child:

    prepare_guest_reply(
        backend_receipt,
        guest_task,
        vm_generation,
        descriptor_digest,
        result,
        destination,
    )
        -> GuestReplyTicket

    publish_guest_reply_with_apply(ticket, guest_write_and_register_update)
        -> GuestReplyReceipt

The ticket binds the exact commit/backend receipt, root and filesystem ancestry,
current authorized binding, guest task and VM generation, request descriptor,
result, byte range, and destination address. The bounded apply step writes the
validated result bytes and syscall return registers exactly once. Only its
receipt may stage the guest continuation wake and complete the reserved
guest-reply credit.

This split makes a crash after backend completion but before guest reply a
discoverable committed obligation. A replacement queries and resumes that
obligation without recommitting the device request or inventing a backend
result.

### Failure windows

Required injections include service crash after device commit and before
backend completion, crash after backend outcome recording and before reply
creation, after reply creation and before guest mutation, after guest mutation
and before Registry acknowledgement, stale service reply, wrong backend receipt,
guest remap or VM-generation change, duplicate reply, reply versus revoke, and
reply versus replacement isolation. Validation failure before guest mutation is
failure atomic. If interruption after guest mutation but before acknowledgement
is representable, the guest remains fenced and only the exact same ticket may
reapply the same bytes and registers; this still counts as one semantic
publication and cannot produce a second wake. Otherwise the obligation remains
retained for explicit reconciliation.

## Deadline and retry generation

### Contract

Every bounded poll, replacement wait, reset retry, and IOTLB retry selected for
the workload belongs to a root-owned `DeadlineSeries`:

    create_deadline_series(root, purpose, attempt_limit)
        -> DeadlineSeries

    arm_deadline(series, generation, clock_basis, bound)
        -> DeadlineTicket

    expire_or_cancel_deadline(ticket, observation)
        -> Expired | Cancelled | Retained | Exhausted

Only one generation per series is active. Each active generation holds one
deadline credit. Expiry, cancellation, and success acknowledgement have one
winner. Retry advances a checked generation and records bounded backoff policy;
attempt or generation exhaustion returns a typed retained/quarantine outcome
instead of wrapping or panicking.

The raw timer IRQ and clock implementation remain TCB. The first implementation
must describe its actual clock basis. If the available OSTD `Jiffies` source
only establishes callback-count progress, the accepted claim is a callback
count bound, not elapsed wall-clock time or a real deadline.

### Failure windows

The matrix must cover arm failure, success racing expiry, cancel racing expiry,
lost or duplicate callback, late callback from an old generation, crash before
expiry acknowledgement, replacement retry, revoke with an active generation,
attempt exhaustion, counter exhaustion, and retained-resource pressure across
backoff. A raw callback carries no authority until matched to the active ticket.

## Request-derived page-fault disposition

### Contract

Raw exception delivery remains TCB. The decision that this fault belongs to the
filesystem service task and must crash that service is root-owned.

Before a service task enters user mode, its `TaskWorkLease` preallocates one
`FaultEvent` slot and service-fault-event credit. When user mode returns with
a page-fault candidate, one Registry transition:

1. validates the task instance, lease, root, domain, binding epoch, VM
   generation, instruction pointer, fault address, and access/error bits;
2. records one immutable service-fault disposition;
3. terminalizes the selected task lease;
4. mints a `ServiceFaultReceipt`; and
5. advances the domain through the normal crash transition.

The receipt is the cause consumed by the supervisor recovery path. It does not
replace the filesystem effect or manufacture a new root. An unexpected guest or
service fault returns a typed isolation outcome; supported profiles must not
panic through the kernel.

### Failure windows

Required injections include failure to reserve the event before user entry,
fault return with the wrong task/binding/VM generation, duplicate exception
delivery, crash after capture but before Registry disposition, root revoke
racing disposition, stale replacement fault, nested or unexpected exception,
counter exhaustion, and supervisor retry of an already consumed fault receipt.
No service task enters user mode without either a reserved event slot or an
explicit typed admission failure.

## Cross-lock, IRQ, and dependency rules

The later implementation mapping must freeze an exact lock hierarchy. Until
that mapping is checked, this RFC does not assert that any current lock order is
correct. The implementation must satisfy these structural rules:

1. `EffectRegistry` core code does not depend on OSTD scheduler, filesystem
   protocol, VirtIO, IOMMU, or guest-memory implementations. Kernel adapters
   depend inward on typed Registry contracts.
2. The standalone VirtIO facade does not import Registry types. Its OSTD adapter
   jointly owns the linear hardware object and opaque obligation ticket.
3. No Registry semantic lock is held across a blocking wait, `Task::run`, raw
   park/unpark, device polling, reset wait, IOTLB wait, or fallible external
   callback.
4. A cross-subsystem operation uses reserve, external apply, and exact
   acknowledgement. The obligation is discoverable before an external mutation
   can become visible.
5. An apply closure executed inside a validated transition is bounded,
   nonblocking, allocation-free after preflight, and documented as infallible.
   Its surrounding lock order is global and the reverse nesting is forbidden.
6. A lock reachable from IRQ context either excludes that IRQ while held or
   uses a documented non-reentrant protocol. IRQ code presents a staged ticket;
   it does not scan or reconstruct root state.
7. Queue publication preserves initialization-before-`avail.idx` Release.
   Completion consumes it with the required Acquire edge. Guest wake similarly
   preserves outcome publication before unpark Release and waiter observation
   after Acquire.
8. Crash/rebind epoch publication and every cross-CPU receipt handoff use
   explicit Release/Acquire or stronger ordering. Volatile access is not a
   synchronization argument.
9. Typed validation, allocation failure, resource exhaustion, stale identity,
   duplicate receipt, and unsupported hardware return typed errors or retained
   isolation. They do not panic in a supported production profile.

The mapping must name each held lock, IRQ state, preemption state, memory edge,
and permitted call direction at every reserve/apply/ack boundary. A unit model
that abstracts the outer lock is supplemental evidence only.

## Additive causal falsification matrix

The existing
`evaluation/production-identity/fault-matrix.toml` is an immutable 35-cell RFC
0001 Phase 1 contract. This RFC must not delete, rename, reorder, relabel,
replace, or advance any of those cells. In particular, its checked model rows
must not be rewritten as production observations.

Implementation work adds the separate machine-readable causal matrix at
`evaluation/production-identity/causal-fault-matrix.toml`. It is additive to
the 35-cell matrix and initially records exactly 66 new rows as planned, grouped
by tranche as 8 queue/DMA preparation, 8 task admission, 11 filesystem service
queue, 9 guest continuation, 10 guest reply, 11 deadline/retry generation, and
9 request-derived page-fault rows. Its families cover every failure window
named in the seven tranches, including each boundary before external mutation,
after external mutation but before acknowledgement, duplicate/replay, stale
binding or generation, wrong identity, revoke/crash race, retry exhaustion, and
retained-credit pressure. The checked-in initial matrix is a prospective
contract and carries no source-mapped or observed execution claim. Every
prospective row therefore records
`current_boundary = planned-contract-no-production-hook`, a unique prospective
injection-point token, and one or more prospective
`path::symbol` targets. The accompanying source paths are context files only:
their existence does not prove that a target symbol, injection hook, shared
production call path, or runtime observation exists.

The separate v2 evidence overlay described below freezes an empty promotion
baseline; it does not currently implement promotion to `source-mapped` or
`observed`. A future structured schema must bind and verify the actual
production boundary, hook, projections, and execution evidence before it may
open either transition. A prospective target is never itself a source or
runtime claim.

The validator freezes the complete parsed matrix with a canonical semantic
SHA-256 computed over deterministic struct-and-sequence serialization. The
digest is held outside the matrix so it is not self-referential. It covers the
failure window, expected disposition, complete identity extensions, CPU and IRQ
requirements, retained disposition, prospective targets, and all before/after
projection values, while allowing comments and TOML layout to improve. Any
semantic update requires an explicit review and digest update.

The combined validator must:

- continue to require the exact original 35-cell population;
- require the exact new causal population and reject missing, duplicate,
  reordered, renamed, fabricated, or extra rows;
- record a precise prospective source target for every planned causal row and,
  before promotion, bind it to the verified actual production boundary and hook
  with its expected complete semantic projection;
- require before/after root, obligation, reverse-index, publication,
  terminalization, and per-class credit projections;
- record CPU, IRQ state, task/binding generation, complete presented identity,
  retained owners, and honest non-success disposition;
- distinguish model checked, source mapped, one-vCPU observed, and 2/4-vCPU
  observed evidence; and
- reject well-formed semantic weakening, not merely missing fields, unknown
  enum variants, or renamed rows.

Passing unit tests, a reference provider, a deterministic state machine, source
inspection, serial markers, or a hard-coded result table cannot promote a
causal cell to observed.

## Locked-empty causal-evidence overlay

The T0 evidence baseline is
`evaluation/production-identity/causal-evidence-overlay.toml`. It is additive:
the v1 causal-coverage ledger and v1 66-cell matrix remain byte-frozen and keep
their original incomplete, fully planned historical meaning. The overlay
records `root-owned-obligation` as vocabulary for request-derived task, fault,
queue, continuation, deadline, device-preparation, and reply authority without
mislabeling those obligations as business effects or raw kernel TCB machinery.

The v2 overlay is intentionally locked by the exact policy
`locked-empty-until-structured-v3`. Its validator rejects every non-empty
`[[promotion]]` array before interpreting any row. It therefore makes no claim
that a source symbol, normal production call edge, injection hook, QEMU run,
artifact, or receipt has been validated. All 66 cells remain `planned`, none is
source-mapped or observed, and `complete` remains false.

Opening promotion requires a separately reviewed schema and validator version;
adding fields to v2 or weakening its empty-log rule is not an accepted path. At
minimum that structured v3 gate must:

1. deserialize the complete frozen `BaseCell` contract and bind each promotion
   to its exact `production_symbols`, `source_paths`, unique target injection
   hook, expected disposition, before/after projections, and CPU and IRQ
   requirements;
2. prove a reviewed normal-workload call path to the exact production adapter
   and hook without treating an unrelated same-named path, method, macro, test,
   feature-only helper, or arbitrary identifier reference as a call edge;
3. retain a full source-mapping digest and require an observation at the same
   exact Git revision and mapping digest;
4. parse a fixed, versioned, `deny_unknown_fields` execution receipt that binds
   the cell, revision, injection hook, QEMU profile, artifact SHA-256, complete
   before/after projection, disposition, vCPU count, and IRQ mode;
5. accept only registered QEMU profiles whose CPU and IRQ properties satisfy
   that cell, and reject empty, unrelated, or multiply substituted artifacts;
6. restrict artifacts and receipts to an explicit retained-evidence root,
   reject a symlink in every path component, prove canonical containment, and
   bind archive or Git-manifest identity rather than accepting an arbitrary
   worktree file;
7. validate evidence dates and their order, including `recorded_on <= as_of`;
   and
8. bind every row to its predecessor digest and an externally reviewed history
   anchor so swapping and renumbering rows cannot masquerade as append-only
   history.

Even a future valid per-cell promotion does not by itself change the v1
boundary classification or satisfy the ledger acceptance conditions below.

## Ledger and evidence acceptance

This RFC alone must not change
`evaluation/production-identity/causal-coverage.toml`. A boundary may leave
`uncovered-gap`, and the summary or `complete` fields may change, only after
all of the following are true:

1. the normal Linux filesystem workload creates and consumes the obligation in
   the shared production `EffectRegistry`;
2. the same production call sites serve normal, crash/replacement, revoke, and
   retained recovery paths without an evaluation-only substitute;
3. focused tests, negative substitutions, and conservation checks pass;
4. the additive causal matrix executes its required rows through those shared
   call sites and records complete before/after projections;
5. exact-source, clean-worktree local evidence and exact pushed-revision CI
   evidence bind the implementation and artifacts; and
6. the claim ledger records the remaining limitations, including polling,
   one-vCPU, callback-count time, unsupported generic IOMMU, or absent persistent
   recovery wherever they still apply.

Static source mapping may prepare an evidence contract, but it does not satisfy
item 1 or change a classification. One-vCPU evidence cannot satisfy the later
RFC 0001 SMP gate. A synthetic registry, case-local ledger, host adapter, or
replayed native transcript cannot substitute for shared OSTD production-path
observation.

## Exit condition

This RFC's causal-closure design is implemented only when all seven tranches
are used by the bounded normal workload, all request-derived obligations are
root-indexed and credit-conserving, every named failure window has an additive
matrix row, and the current eight gaps are either observed as closed through
the shared production path or narrowed to an explicitly reviewed low-level TCB
sub-operation without hiding request policy.

That implementation result still does not, by itself, close RFC 0001. Real IRQ,
reset and IOTLB completion, 2-vCPU and 4-vCPU refinement, supervisor integration,
resource-pressure soak, production error-path hardening, and exact release
evidence retain their independent gates.
