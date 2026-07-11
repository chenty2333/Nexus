# Mediated VirtIO CSER refinement

`IoCser.tla` is the Stage 5 successor to the baseline `Cser.tla` and pager
refinement `PagerCser.tla`. It fixes the protocol boundary for one CSER scope
that exclusively owns one split `virtio-blk` queue and its device. The scope
contains two kinds of DMA lease:

- one queue lease, including the descriptor, avail, and used rings;
- one request lease for every prepared request, including its frame, IOVA,
  mapping identity, queue slot, and one renewable lease credit.

The model keeps two independent accounting ledgers:

- **renewable lease credits** cover queue/request DMA ownership and return only
  after the corresponding synchronous IOTLB acknowledgement;
- **nonrenewable commit charges** are reserved by an accepted `Register`, move
  from `Held` to `Spent` at `PublishAvail`, and return to the free pool only if
  the request is cancelled before publication.

A completed or reset request returns its renewable DMA lease but does not
refund its spent commit charge. Quiescent closure therefore requires all lease
credits to be free and no commit charge to remain `Held`; it deliberately does
not require all commit charges to be free.

The exclusive ownership assumption matters. `ResetAck` may terminalize every
still-committed request in this bounded scope because reset cannot destroy an
unrelated scope's queue. A shared or multi-tenant queue needs another model and
cannot reuse this reset rule.

## Independent generations

Every request token carries three independent fences:

```text
IoRequestToken {
    scope
    request
    authority_epoch
    binding_epoch
    device
    queue
    device_generation
}
```

Only these transitions advance them:

| Generation | Transition | Meaning |
| --- | --- | --- |
| `authorityEpoch` | `RevokeBegin` | closes the old submission/commit gate |
| `bindingEpoch` | service `Crash` | rejects replies from the failed I/O service |
| `deviceGeneration` | successful `ResetAck` | fences old and duplicate device completions |

`Ready`, `Rebind`, `Adopt`, `Notify`, reset timeout, and every retry leave all
three unchanged. In particular, a service crash does not pretend that the
device stopped DMA, and revocation does not itself pretend that reset
completed.

An accepted `RegisterAttempt` captures all three token generations, including
the current device generation. `PublishAttempt` does not fill in or refresh a
missing device generation later.

After `Crash`, the kernel scheduler fallback is the only unconditionally fair
recovery action. A replacement first reports `Ready`, then becomes `Bound`.
Only `Registered` and `Prepared` requests may be explicitly adopted into that
new binding. `Committed` requests remain owned by the kernel/device completion
path and are never adopted.

## The split-ring commit point

The request path is:

```text
Register
  -> Prepare descriptor + request DMA lease
  -> write avail ring entry
  -> release fence
  -> present full RequestToken
  -> Release publication of avail.idx       valid PublishAttempt / COMMIT
  -> optional notify                        only a hint
```

The accepted branch of `PublishAttempt`—named `PublishAvail` at the concrete
VirtIO boundary—is the commit linearization point. A conforming device may
poll the ring, observe the new `avail.idx`, and start DMA before the driver
writes a notification register. Consequently:

- descriptor construction and the avail-ring entry remain cancellable before
  the Release publication;
- `Notify` is neither commit nor proof that the device first observed the
  request;
- after publication, software cannot remove one live descriptor and claim the
  effect never happened;
- a published write or flush is not rolled back by later reset.

The abstract transition does not prove a Rust or architecture-specific memory
barrier implementation. It fixes the ordering that the mediated VirtIO slice
must refine and test.

Every bounded publish attempt presents the generation-bearing fields of this
typed token:

```text
RequestToken {
    scope
    request
    authority_epoch
    binding_epoch
    device
    queue
    device_generation
}
```

All finite authority, binding, and device-generation combinations are
presentable while rejection history has room. Scope, request, device, and queue
identity are fixed to the already selected request record; the finite model
does not enumerate cross-request or wrong-device integer tokens. A concrete
portal must exclude those inputs with an unforgeable typed handle before this
generation gate. Only a token matching the captured generations and all
current gates can publish. A stale token, a token presented while the service
is down, a post-revoke token, and the old binding token retained across `Adopt`
all take an explicit bounded reject transition. Rejection may update only its
audit count/reason; action properties check that request state, DMA ownership,
queue state, both ledgers, and unrelated audit history are unchanged. The
liveness configuration allows one stale rejection followed by a fresh accepted
token for the same request.

## Request terminal outcomes

The model distinguishes three terminal outcome classes:

```text
Registered -------------------------------> Cancelled

Prepared -> Cancelling -> IOTLB Ack ------> Cancelled

Committed -> DeviceComplete --------------> Completed
          \
           -> whole-device ResetAck ------> IndeterminateAfterReset
```

A prepared request has a real DMA mapping even though the device cannot yet
discover its descriptor. Revocation can therefore remove its queue slot and
start unmapping without waiting for device reset, but it remains
`Cancelling`—not `Cancelled`—until synchronous IOTLB invalidation completes.
Only then may the frame and IOVA become reusable and the credit return.

`DeviceComplete` establishes per-request quiescence, so a completed request's
lease can likewise be unmapped without waiting for whole-device reset. The
scope's queue lease is different: a polling device can continue to read queue
memory even when there are no committed requests. Closing the scope therefore
always requires whole-device `ResetAck` before queue unmap, including an empty
queue.

`DeviceComplete` and `ResetAck` compete atomically:

- if the current-generation completion wins, the request is `Completed` and
  reset leaves that outcome unchanged;
- if reset acknowledgement wins, every request still `Committed` becomes
  `IndeterminateAfterReset` and the device generation advances;
- an old-generation completion after reset, or a second completion after a
  prior terminal outcome, is rejected and cannot terminalize the request
  again.

`IndeterminateAfterReset` is deliberately not named `Aborted`. It means the
device has stopped future access, but the model cannot know whether an already
published block write reached media.

Every request has **at most one** terminalization transition. If its state is
terminal, its terminal counter is exactly one; an unused or still-live request
has counter zero. The model does not claim that every environment-controlled
request eventually becomes terminal.

## Revocation, reset, and DMA closure

The successful closing path is a fork/join, not a serial pipeline:

```text
RevokeBegin
  -> authorityEpoch++ / Active -> Closing / stop submissions
  |
  +-- Registered -> Cancelled / return held commit charge
  |
  +-- Prepared -> Cancelling / return held commit charge
  |      -> request unmap -> request IOTLB Ack -> Cancelled
  |
  +-- already DeviceComplete request
  |      -> request unmap -> request IOTLB Ack -> lease returned
  |
  `-- BeginReset
         -> ResetAck / deviceGeneration++
         -> remaining Committed -> IndeterminateAfterReset
         -> their request unmap/invalidate/Ack
         -> queue unmap/invalidate/Ack

all branches acknowledged and all lease credits returned
  -> RevokeComplete / Closing -> Revoked
```

Request cleanup may run independently as soon as its invisibility or
per-request completion makes that safe. Queue cleanup cannot cross its unmap
gate until reset acknowledgement has made the whole device quiescent.

`RevokeComplete` is legal only when:

- whole-device reset has acknowledged and the device generation advanced;
- the queue lease is synchronously invalidated and reusable;
- every terminal request has terminalized at most once, and every registered
  request from the closing authority epoch is terminal at completion;
- every request lease is absent or synchronously invalidated;
- no queue slot, tombstone, frame, IOVA, mapping record, or held credit
  remains.

This is quiescent closure, not rollback.

The reset state machine exists only after `RevokeBegin`; this model has no
active-scope operational reset. `scopeState = Active` implies reset is `Idle`,
its attempt count is zero, and the device generation remains at its initial
value. A later operational-reset refinement must add and re-check that path
explicitly rather than reading it into this model.

## Honest timeout and retry

Reset and IOTLB invalidation acknowledgements are hardware/environment
actions. The specification gives them no fairness assumption.

On `ResetTimeout`:

- the scope stays `Closing`;
- the queue frame, IOVA, mapping record, and lease credit remain held;
- every still-`Committed` and therefore device-visible request lease remains
  mapped and held;
- no request becomes `IndeterminateAfterReset`;
- `RevokeComplete` remains disabled.

On request or queue invalidation timeout, the same target retains its frame,
IOVA, mapping identity, non-reusable state, and lease credit as a tombstone. A retry
uses the same retained identity, so a late acknowledgement for that target is
safe; no mapping or frame has been recycled in between. The bounded model
allows one explicit retry after the first attempt. It also explores a final
timeout with no further retry, in which the scope correctly remains
`Closing` forever instead of manufacturing success.

## Fairness and liveness claims

Only kernel-owned processes are weakly fair:

- scheduler fallback after service crash;
- cancellation of old-authority unpublished requests;
- starting a requested whole-device reset;
- beginning a safe request or queue invalidation;
- publishing `Revoked` after every real acknowledgement has already made
  `ReadyForRevokeComplete` true.

The I/O service, replacement service, device completion, reset acknowledgement,
timeouts, IOTLB acknowledgement, and all retries are not fair. The model checks
the conditional property
`ReadyForRevokeComplete ~> scopeState = "Revoked"`; it intentionally does not
claim `Closing ~> Revoked`. Hardware can fail permanently, and a retained
tombstone is then the correct terminal system condition even though the scope
has not completed revocation.

## Checked properties

Together, the two checked configurations cover:

- type-safe request tokens and independent generation domains;
- separate conservation of renewable lease credits and nonrenewable commit
  charges;
- a real bounded `RegisterReject` transition when a request ID exceeds commit
  capacity, with no ledger or request-state side effect;
- generation-token publish enabledness for an already typed request identity,
  bounded rejection history, and semantic side-effect freedom for rejected
  publish attempts;
- the `avail.idx` publication occurring at most once per request;
- post-revoke publication exclusion;
- at most one request terminalization, with every terminal state having count
  exactly one;
- current-device-generation completion acceptance and stale/duplicate
  completion rejection;
- old service bindings being unable to publish without explicit adoption;
- `Ready` before `Rebind`, and no adoption after closing;
- no frame, IOVA, or mapping identity becoming reusable before synchronous
  invalidation completion;
- honest reset/request/queue timeout tombstones;
- `ResetAck` preceding queue teardown and reset terminalization never being
  mislabeled as cancellation;
- quiescent closure with no held lease credit, DMA resource, or held commit
  charge, while spent commit charges remain accounted;
- the narrow kernel-only progress properties listed above.

The model is deliberately split into two gates. Combining symmetry reduction
with temporal checking causes TLC to warn that it may miss liveness violations,
so Nexus does not treat such a run as evidence.

`IoCserSafetyMC.cfg` checks state invariants with request-ID symmetry and **no
temporal properties**. It has three request IDs, two commit charges, two
request lease credits plus the queue lease, one publish attempt per request,
and two completion/cleanup attempts. The third ID can execute a real
`CommitBudgetExhausted` rejection after the first two reserve the capacity.
Two requests can commit concurrently, allowing `DeviceComplete` to win for one
and `ResetAck` to produce `IndeterminateAfterReset` for the other. The complete
safety quotient is:

```text
21,998,796 states generated
4,151,240 distinct states found
0 states left on queue
complete graph depth 39
temporal branches: none
```

`IoCserMC.cfg` checks every action property and weak-fair liveness property
without symmetry. It has two IDs but only one commit charge/request lease, so
the second ID still executes the real exhausted registration rejection. It
allows two publish attempts: an adopted request may reject its old-binding
token and then accept the fresh token. Its complete graph is:

```text
1,138,855 states generated
269,645 distinct states found
0 states left on queue
complete graph depth 29
5 temporal branches
```

The checked script additionally runs two expected-counterexample reachability
gates against the safety configuration. They fail only the deliberately added
`CoverageWitnessAbsent` and `MixedResetOutcomesAbsent` invariants, proving that
the graph contains:

- a single trace in which `RegisterReject` is caused only by an exhausted
  commit budget while every registration gate remains open, and
  `PublishReject` is caused only by a stale presented binding while the
  authority, request, device generation, DMA, queue-slot, and service gates
  remain fresh;
- a trace containing distinct `Completed` and `IndeterminateAfterReset`
  requests.

These are reachability witnesses, not safety failures. The script rejects an
unexpected TLC error or a missing witness.

## Run and regenerate

The supported entry point runs the full safety graph, both reachability
witnesses, and then the no-symmetry action/liveness graph:

```sh
./x spec
```

Inside the pinned development container, the same combined I/O gate is:

```sh
TLA2TOOLS_JAR=/path/to/tla2tools.jar ./specs/cser/check.sh IoCser
```

The commands below document the lower-level steps that `xtask` performs inside
that pinned container; they are not a second supported host toolchain. To
regenerate or run either complete graph manually in the container:

```sh
cd specs/cser
java -cp "$TLA2TOOLS_JAR" pcal.trans \
  -nocfg -lineWidth 10000 IoCser.tla
java -XX:+UseParallelGC -cp "$TLA2TOOLS_JAR" tlc2.TLC \
  -workers auto -cleanup -config IoCserSafetyMC.cfg IoCser.tla
java -XX:+UseParallelGC -cp "$TLA2TOOLS_JAR" tlc2.TLC \
  -workers auto \
  -cleanup -config IoCserMC.cfg IoCser.tla
```

Edit the PlusCal block rather than the generated transition relation, then
regenerate before checking. The repository verification entry point compares
a fresh translation against the checked-in file before starting either graph.

## Model boundary

This is a protocol successor model, not a VirtIO or IOMMU implementation. It
does not model PCI discovery, MSI/MSI-X masking, transport negotiation, packed
rings, indirect descriptor layout, event-index arithmetic, multi-queue devices,
actual interrupt draining, cache coherence, SMP barriers, VT-d queue/register
ownership, IOTLB command encoding, invalidation wait-queue races, physical
deadlines, frame allocator reuse, persistent-media ordering, or recovery of a
device shared with another authority scope.

The first implementation must refine the model with `virtio-drivers` behind a
Nexus mediation/HAL boundary and with an OSTD IOMMU API that returns success
only after synchronous invalidation completion. Until QEMU with a real IOMMU
path observes reset completion, invalidation completion, and fenced frame
reuse, this specification is evidence for the abstract protocol only—not a
claim that production DMA closure is complete.
