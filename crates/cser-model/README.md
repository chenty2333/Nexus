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

The `personality` module is the bounded Stage 6A oracle for a restartable
user-space Linux syscall personality. It adds:

- one full-identity `SyscallToken` per blocked task, carrying scope, syscall,
  task, operation label, authority epoch, and personality-binding epoch;
- `write` follows `Capture -> PrepareReply -> BackendCommit -> Reply`: prepare
  retains only a candidate label, backend commit publishes exactly one
  kernel-owned output obligation, and the later reply only resumes the guest;
- `exit_group` follows `Capture -> PrepareReply -> Reply` and publishes one
  process-terminal delivery without acquiring a backend output obligation;
- distinct successful deliveries for `write` return and `exit_group`
  termination request, plus kernel abort, so exactly one of resume, exit, or
  abort is recorded for every terminal continuation;
- `Crash -> FallbackPick -> RecoverySnapshot -> Ready -> Rebind -> Adopt`,
  where only `Crash` advances the binding epoch, prepared and backend-committed
  work cannot be published by its old binding, and rebind never adopts an
  orphan implicitly; after adopting backend-committed `write`, a replacement
  may publish the outstanding reply but cannot commit another obligation;
- `RevokeBegin -> RevokeNext* -> RevokeComplete`, which closes the old
  authority epoch before walking the target scope-local reverse index;
  uncommitted continuations abort, while a backend commitment that linearized
  first is drained to its single reply without another backend commit;
- a blocked-task index that forbids two simultaneous syscall continuations for
  one task and is released only by the unique terminal transition.

`write` and `exit_group` are operation labels, not syscall implementations.
The model contains no ELF loading, Linux UAPI decoding, descriptor table,
process-group, signal, I/O, or external-side-effect semantics. In particular,
`BackendCommit` is an abstract at-most-once output obligation: it neither
executes a console write nor proves a real portal, driver, or mediated VirtIO
commit. The bounded OSTD Stage 6A slice refines it to one kernel-owned serial
publication; after crash/rebind/adopt, the replacement completes the outstanding
guest reply without issuing the output again. A separate companion scope
observes kernel closure drain a committed obligation after authority closure.
Neither path is a general backend or device proof. The model also assumes
kernel closure can finish an already committed obligation and publish its one
guest reply after authority closure; it does not model a
stuck backend or timeout/tombstone for this syscall path. Tokens store
inspectable fields rather than implementing opaque kernel capabilities, and
the sequence/property tests do not establish production Rust concurrency,
kernel scheduling fairness, or whole-system liveness. The separate
`PersonalityCser.tla` PlusCal refinement fixes the bounded temporal protocol and
recovery/closure progress assumptions; neither artifact proves the production
implementation. CSER therefore remains a candidate mechanism rather than an
established contribution.

The `personality::futex` module is the Stage 6B.1 successor oracle. It embeds
one `PersonalityModel`, which remains the sole owner of authority and binding
epochs, crash/fallback/ready/rebind state, snapshot revision, and the scope
revoke gate. The successor contributes a bounded private-futex registry rather
than a second authority registry. Its two internal refinement hooks validate a
current binding and publish futex-state changes into the shared snapshot
revision. The embedded Stage 6A syscall registry is empty in this successor;
futex live effects and blocked tasks use separate local indexes. This proves
reuse of one lifecycle gate, not a unified syscall+futex reverse index,
cross-type blocked-task exclusivity, or whole-system scope closure.

The model covers one configured private key per scope. A key contains address
space identity and generation plus a four-byte-aligned virtual address. A
successful `wait_register` is one abstract compare/credit/enqueue
linearization point. A value mismatch returns `Again` without allocating an
effect ID, blocking a task, changing the queue, or consuming a wait credit; the
immediate Linux `EAGAIN` reply itself remains outside this asynchronous-effect
model. `wake_commit` consumes one separate wake-continuation credit, creates a
wake continuation, and freezes both its FIFO selection and its zero-or-one
return count. The later kernel-owned publication terminalizes that wake and, if
selected, exactly one wait without consulting the queue again.

Crash arms one kernel recovery watchdog over the exact old-binding live cohort.
Snapshot/ready/rebind use the shared gate, while each futex effect must be
adopted explicitly. Adoption changes only its binding fence. When every cohort
member is adopted or terminalized, the timer credit returns even if an adopted
wait remains normally queued without a Linux timeout. Watchdog expiry instead
enters the same scope revocation path as explicit closure and yields `Aborted`,
never `TimedOut`. Closure drains a wake that committed first, aborts a wait for
which revocation won, and requires empty queue/live/blocked-task indexes plus
returned wait, wake, and timer credits before completion. Internally, a
`VecDeque` supplies the FIFO head and a scope-local `BTreeSet` supplies the next
committed wake; closure does not rescan all live effects or any unrelated
scope. The executable oracle records index selections and tests an unrelated
`N=96` population. B-tree maintenance still costs `O(log k)`, so this is a
target-local structural bound rather than a production `O(k)` latency claim.

This is a sequential executable oracle, not a production futex implementation.
It has no requeue, guest-memory fault model, Linux timeout/timespec, signal or
spurious-wake handling, shared/PI/robust futex state, address-space teardown,
SMP ordering, real waiter/waker, or unified cross-service registry. The modeled
word is an input to the compare point and has no user-store transition, so this
artifact does not prove lost-wakeup or memory-order behavior. Capture and
successful wait registration, and capture and wake commit, are deliberately
folded into their respective abstract linearization points. Full token identity
therefore applies to an already registered wait or committed wake and its later
snapshot/adopt/publication/closure paths; it does not cover a pre-registration
or pre-commit captured syscall packet. The separate
`PersonalityFutexCser.tla` successor fixes the bounded temporal and fairness
contract. Together these artifacts complete the Stage 6B.1 semantics
checkpoint.

The independent pinned OSTD/QEMU slice refines that predecessor oracle with a
real shared `VmSpace`, separate waiter/waker `UserContext`s, atomic user-word
loads, one guest `xchg` store, real personality faults, fresh-v2 rebind/adopt,
kernel wake publication, watchdog cancel/expire, and failure-atomic post-revoke
token rejection. Its `recover` and `expire` traces both finish with exactly two
terminalizations, empty local futex indexes, and all wait/wake/timer credits
free. That makes Stage 6B.1 **semantics complete and bounded implementation
slice complete / Observed**, but does not widen this executable oracle's model
boundary. The observation remains one private key, one waiter, one waker,
`max_wake = 1`, and one CPU; it has no Linux timeout, requeue, clone, mmap,
thread-exit, lost-wakeup/SMP proof, or unified syscall/futex registry. The
Stage 6B.2 successor below adds a separate common-registry refinement and
retained workload receipt; it does not change this 6B.1 model's finite boundary.

The `personality::registry` module is the common Stage 6B.2 executable
foundation for Linux-personality effects. It centralizes authority and binding
fences, opaque full-identity handles, typed renewable credits, the exclusive
blocked-task slot, scope/task/resource reverse indexes, immutable origin plus
mutable current resources, atomic batch commit/resource movement, publication
acknowledgement, exact crash snapshots, ready/rebind/explicit adoption, and
scope-local revoke closure. Domain refinements retain their semantic queues and
receipts. This registry is personality-local; scheduler, pager, and mediated
VirtIO still use independent state machines.

`personality::futex_requeue` builds two-key private futex semantics over that
registry. A wait keeps one immutable origin key while its current resource may
move from A to B. `RequeueCommit` atomically freezes disjoint woken and moved
sets, commits the controller and selected wake, updates generic and typed
resource membership together, and returns Linux's `woken + requeued` count.
The moved waiter preserves identity and held wait credit. FIFO selection cannot
skip an unadopted old-binding queue head, and a replacement cannot select old
work until explicit adoption. The bounded model fixes `max_wake <= 1` and
`max_requeue <= 1` but permits longer source and target queues.

`personality::readiness` fixes the reusable mechanism below epoll-like ABIs:
generational sources and subscriptions, atomic sample-and-arm, LT/ET/ONESHOT
selection, immutable delivery batches, a positive timeout effect, and one
winner among ready, timeout, and revoke. Crash recovery requires an exact
snapshot and explicit adoption; stale source/service/subscription generations
and duplicate publication reject without mutation. It deliberately owns no fd
table or Linux epoll syscall decoding.

`personality::exec` keeps staged segments and `ExecLayout` TLS/stack metadata
kernel-private until one all-or-nothing `ExecCommit` changes the current image.
A pre-commit crash requires adoption of the controller and every segment.
Revocation before commit aborts staging and preserves the previous image;
revocation after commit drains once and never restores the old image. Unlike
the concrete QEMU receipt, this Rust abstraction records TLS and stack as
frozen layout metadata rather than two additional effects.

The current executable suite contains 117 tests. The four Stage 6B.2 additions
contribute 12 common-registry tests, 10 futex-requeue tests, 7 readiness tests,
and 7 exec tests; deterministic sequences and bounded proptests cover rollback,
stale projections, current-binding fencing, single-terminal closure, and typed
credit conservation. These are sequential safe-Rust reference transitions,
not the eventual production lock/atomic scheme or an SMP proof.

The pinned OSTD/QEMU successor independently executes the adapted retained
Round 4 futex program, the adapted retained Round 5 epoll program plus a
readiness lifecycle companion, and a retained dynamic PIE launcher/main/
interpreter path. Those bounded observations complete four of the six core
Linux pressure inputs when combined with `linux-hello`; runtime filesystem and
runtime network remain pending. They do not establish a cross-service registry
or complete Stage 6.

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

The library is `no_std + alloc` compatible and contains no unsafe code. The
baseline `Model` trace action names and fields are shared with the baseline
TLA+ model and the OSTD scheduler spike under `experiments/ostd-cser-spike`.
