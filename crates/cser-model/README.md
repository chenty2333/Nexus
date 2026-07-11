# CSER reference model

`cser-model` is the executable Rust oracle for Causally Scoped Effect
Revocation. It fixes the same linearization contract as
`specs/cser/Cser.tla` without depending on the legacy Nexus kernel.

The model covers:

- authority and supervisor binding epochs;
- `Register -> Prepare -> Commit -> Complete`;
- `RevokeBegin -> RevokeStep -> RevokeComplete`;
- supervisor `Crash -> FallbackPick -> Rebind -> Adopt`;
- per-scope live-effect indexes and target-local revocation selection;
- single terminalization and scalar budget conservation.

The `pager` module is the executable oracle for the Stage 4 successor
protocol. It adds:

- distinct authority, pager-binding, and address-space generations;
- a full-identity one-shot fault token carrying scope, fault, address space,
  thread, page, access, and all three generation fences;
- `Register -> PrepareZero -> Commit -> Complete`, where `Commit` atomically
  publishes one `(address space, generation, page)` mapping slot and consumes
  the continuation, and `Complete` publishes its only successful wake/resume;
- same-page `SatisfyMapped`, where a losing fault shares the one current
  publication, returns its held credit, releases a redundant prepared frame,
  and completes successfully without publishing a second mapping;
- `Crash -> FallbackPick -> RecoverySnapshot -> Ready -> Rebind -> Adopt`,
  with `Crash` as the only binding-epoch increment and explicit per-fault
  adoption after replacement readiness;
- unique prepared-frame ownership retained across crash, transferred to the
  mapping at commit, or released exactly once by coalescing, stale/closing
  abort, or address-space teardown;
- timeout `RevokeBegin -> RevokeNext* -> RevokeComplete`, held-credit return,
  and exactly `k` abstract closure steps selected from the target scope's
  reverse index without visiting unrelated scopes;
- stale old-binding and address-space-generation rejection before mapping,
  continuation, or thread-state mutation.

Current mapping ownership and immutable publication history are separate.
Address-space generation mutation is rejected while any mapping publisher is
still `Committed`; after its continuation reaches `Completed`, mutation removes
the current PTE abstraction, releases the mapped frame, returns its page/pin
credit, and retains the historical publication witness. A later generation may
therefore publish the same virtual page again without erasing evidence that the
old generation published it once.

The pager's scalar budget is specifically a renewable page/pin-retention
credit, not an irreversible external-effect charge: `Commit` records it as
`Spent` while the mapping is installed, and generation teardown moves it to
`Returned`. This refinement does not change the baseline rule that genuinely
irreversible effects cannot be refunded by revocation.

The public kernel `abort` transition is deliberately unavailable for arbitrary
Active, current-generation faults. It is accepted only for a stale address-space
generation or an already Closing scope. Normal same-page losers use
`SatisfyMapped`; recovery failure uses scope timeout/revocation.

The one-shot result is enforced by the continuation/effect state transition,
not by an assumed one-shot wake primitive. A backend waker may be callable more
than once; only the actor that changes the model from pending to resolved or
aborted is allowed to publish the single terminal notification.

The first live registration arms a kernel-owned recovery deadline, and
`Crash -> Ready -> Rebind` does not disarm it. `recovery_timeout_begin` is the
watchdog's explicit closure entry. It requires neither a pager binding nor an
individual fault token, so it remains authorized whether a replacement never
adopted a fault or adopted it without committing. The timeout and mapping
`Commit` choose one linearization order. If the batch contains no uncommitted
fault, expiry enters a completion-only state, gates new registration, and
permits trusted kernel `Complete` operations to drain the batch;
`DeadlineComplete` then returns the watchdog to idle without revoking the scope.
This remains true if the pager crashes before or after completion: the deadline
protects blocked fault continuations, not the service lease, while fallback
state separately records pager absence. If any uncommitted fault remains,
timeout fences its commit, detaches the pager, closes the scope, and aborts held
effects. An empty crash does not arm deadline work, and the final early terminal
transition may fuse deadline cancellation.

The Rust model checks the safety of transitions that a driver actually invokes;
its sequential and property tests do **not** prove that a watchdog, completion,
or closure step is eventually scheduled. Kernel-only weak fairness and the
resulting liveness property belong to `specs/cser/PagerCser.tla`. No fairness is
assigned to replacement pager actions in either model.

The pager Loom suite is a deliberately small concurrency refinement of four
critical publication and terminalization gates: `Commit` versus timeout under
one scope gate; adopt versus timeout and a stale reply; complete, abort, and a
duplicate reply contending for one wake authority; and the three-stage
`Closing -> cleanup/wake-authority destruction -> Revoked` ordering. It uses
small `loom::sync` surrogate state machines rather than executing `PagerModel`
or the OSTD spike. A passing run establishes only those bounded interleavings;
it does not prove liveness or fairness, the eventual production lock/atomic
scheme, OSTD task or waker behavior, real page-table allocation or PTE
publication, TLB/SMP visibility or shootdown, multi-client recovery, device
I/O, DMA/IOMMU quiescence, or whole-system CSER composition.

The reference model stores each reverse index in a `BTreeSet`. Its tests prove
the structural property that closure visits exactly the target scope's `k`
live effects and does not scan the global population `N`; they do not prove a
strict `O(k)` wall-clock bound because tree selection and removal add
data-structure cost. A production complexity claim requires an appropriate
kernel index plus fixed-`N`/varying-`k` and fixed-`k`/varying-`N` measurements.

The pager model deliberately stops before real page tables and TLB shootdown.
`FrameId` denotes one allocation identity, so a safely recycled physical frame
would receive a fresh identity. A successful mapping remains publication history
after address-space generation teardown, but it is no longer a current mapping;
only a fault that is already stale when it attempts `Commit` is rejected.

The `io` module is the executable oracle for the Stage 5 mediated VirtIO
protocol. One scope exclusively owns one split queue and device. It adds:

- independent authority, user-service binding, and device-reset generations;
- typed conservation of queue slots, pinned pages, DMA bytes, and a separate
  non-renewable commit charge;
- `Register -> Prepare -> PublishAvail`, where registration reserves a typed
  grant and fresh DMA identity, `Prepare` establishes the mapping and exactly
  one queue-slot obligation, and the `Release` publication of split-ring
  `avail.idx` is the only request commit point; `Notify` is a one-shot
  post-commit hint because a polling device can observe the request without it;
- `Crash -> FallbackPick -> RecoverySnapshot -> Ready -> Rebind -> Adopt` for
  `Registered`/`Prepared` work, while `Committed` work remains kernel-owned;
- separate scope-local indexes for retained DMA cleanup, unpublished work, and
  live queue-slot obligations, plus incremental held-charge and nonterminal
  counters. Cancellation selection and closure do not traverse immutable
  request history, so already terminalized and synchronously invalidated
  history does not increase the frozen revocation target `k`;
- `Registered -> Cancelled` for a request with no DMA mapping, and
  `Prepared -> Cancelling -> Cancelled` only after request unmap plus a matching
  synchronous IOTLB invalidation acknowledgement;
- `Committed -> Completed` on a matching current-device-generation completion,
  or `Committed -> IndeterminateAfterReset` when whole-device `ResetAck` wins;
  reset never calls a published request cancelled and never claims rollback;
- early independent cleanup for never-published `Cancelling` requests and
  device-completed requests, while the scope-owned queue and any still-visible
  committed work remain retained until whole-device reset acknowledgement;
  queue unmap additionally waits until every prepared/committed request has
  relinquished its descriptor-slot obligation;
- reset and per-lease invalidation timeout tombstones. A timeout value carries
  the retained queue/request identity and typed credit summary, the scope stays
  `Closing`, and only an explicit retry can resume cleanup;
- queue and request DMA release only after unmap plus synchronous invalidation
  completion. Lease and mapping IDs are never reused; an IOVA becomes reusable
  only after acknowledgement and only with fresh identities.

`RevokeBegin` closes the publication gate but does not serialize all cleanup.
Whole-device reset may run in parallel with cancellation and invalidation of
unpublished requests. `ResetAck` affects only requests still `Committed` at its
linearization point. `RevokeComplete` requires reset-established device
quiescence, a synchronously invalidated and released queue lease, every request
effect terminalized exactly once, every request lease released, no held commit
charge, and full renewable-credit return. An invalidation timeout therefore
cannot be disguised as closure or ordinary `Drop`.

The I/O Loom suite uses three small surrogate gates: `PublishAvail` versus
`RevokeBegin`; device completion versus `ResetAck`; and reset/invalidation
timeout versus acknowledgement and resource release. Passing it establishes
only those bounded lock/atomic interleavings. It does **not** prove the real
virtio-drivers publication fence, PCI reset semantics, interrupt suppression,
OSTD synchronization, VT-d command completion, hardware cache behavior, DMA
quiescence, or whole-system liveness. Those require the Stage 5 OSTD/QEMU spike
and fault injection.

The I/O oracle's closure predicate is constant-time over incremental counters
and index emptiness. Each unpublished cancellation selects and removes one
entry directly from its dedicated `BTreeSet`; `ResetAck` visits the remaining
live-obligation index once. Across `k` live requests, the reference structure
therefore performs `O(k)` logical visits without scanning immutable per-scope
history or unrelated scopes. Request records still live in one global
`BTreeMap`, however, so those visits currently add `O(log N)` global lookup
cost in addition to local-set selection/removal and other global ownership
indexes. The concrete model therefore has logarithmic costs in both local and
global indexed populations; it is not independent of global scale. This is
useful no-global-scan evidence, but it does not establish WorkProportionality.
A production implementation needs a scope-local or intrusive record index plus
the fixed-`N`/varying-`k` and fixed-`k`/varying-`N` latency curves.

`check_invariants` deliberately performs a full history reconstruction as an
explicit diagnostic audit; it is not called by any protocol transition or
closure predicate and is excluded from the revocation-work bound.

`Commit` is the effect commit linearization point. `RevokeBegin` atomically
closes the old authority epoch. Effects that committed first must complete or
drain; effects for which revocation won must abort. The model does not promise
rollback after an external effect crossed its commit point.

Run every model gate and the canonical trace from the repository root through
the pinned Docker environment:

```sh
./x model
```

The root entry point runs formatting checks, `no_std` and hosted builds,
Clippy, all deterministic/property/Loom tests, and the canonical trace. Direct
Cargo commands are implementation details of `xtask`; they are not a second
host-toolchain workflow.

The library is `no_std + alloc` compatible and contains no unsafe code. Its
trace action names and fields are shared with the TLA+ model and the OSTD
scheduler spike under `experiments/ostd-cser-spike`.
