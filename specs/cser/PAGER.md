# Pager CSER refinement

`PagerCser.tla` refines the baseline protocol in `Cser.tla` for the first
user-space pager slice. It is a separate successor model: the checked baseline
and its existing `CserMC.cfg` are unchanged.

The modeled CSER scope is one address space. A registered fault creates this
one-shot token:

```text
FaultToken {
    scope                       // the address-space scope
    fault
    authority_epoch
    binding_epoch
    address_space
    address_space_generation
    thread
    page
    access
}
```

The three generations are intentionally independent:

- `Crash` advances only `bindingEpoch` and closes the failed pager's reply
  gate.
- `TimeoutRevoke` advances only `authorityEpoch` and changes the scope from
  `Active` to `Closing`.
- `AddressSpaceChange` advances only `addressSpaceGeneration`, invalidating
  pending replies prepared against the old mapping topology.
- `Ready`, `Rebind`, and `Adopt` do not advance a generation.

Binding zero is the bootstrapped pager. After a crash, `Ready` represents a
fresh replacement having installed its recovery snapshot. `Rebind` is legal
only after both the kernel scheduler fallback is running and that binding has
reported ready. An old `Registered` or `Prepared` fault must then be explicitly
`Adopt`ed. A prepared zero frame belongs to the fault effect, not the crashed
pager, so it remains owned across crash and rebind.

## Linearization and same-page races

`Commit` is one atomic transition that revalidates all of the following before
changing any mapping state:

- the address-space scope is still `Active`;
- a live replacement is fully rebound;
- the authority, binding, and address-space generations all match;
- the continuation is still pending;
- the prepared frame has exactly one fault owner;
- the target PTE slot is empty.

That transition consumes the continuation and publishes the mapping. A fair
kernel `Complete` then wakes its client once. Two bounded faults deliberately
share one page. If they race in the same address-space generation, only one can
publish the slot; `SatisfyMapped` consumes and wakes the loser using the already
committed mapping, returning any redundant prepared frame.

Publication is limited to once per page slot *per address-space generation*,
not once for the lifetime of the model. After every committed continuation has
completed, `AddressSpaceChange` may clear the current slot, release its frame,
advance the generation, and permit one new publication. Historical per-fault
and per-generation counters retain the evidence needed to distinguish a legal
old mapping from a stale reply that first commits after the mutation.

## Deadline closure and fairness

The first `Register` in a batch arms an abstract kernel deadline; later faults
may join while it is armed. `Crash`, `Ready`, and `Rebind` do not disarm a
nonempty batch. A crash with no registered fault does not create a separate
service-liveness deadline in this first slice. Once the deadline is `Expired`,
new registration is closed until the batch is terminal, so a late fault cannot
continually postpone closure.

Deadline phases are monotone across crash: `Armed` remains armed and `Expired`
remains expired. A crash cannot rewind an expired batch or extend its closed
registration window.

Consequently, an empty-cohort crash may remain under the kernel fallback while
waiting for an explicit replacement or higher-level teardown; this model makes
no eventual-rebind or service-liveness claim for that state.

If every batch member terminalizes while the deadline is still `Armed`, a fair
kernel `DeadlineCancel` may atomically clear the batch and return to `Idle`.
`DeadlineCancel` races watchdog expiration: cancellation winning prevents an
expired batch, while expiration winning follows the rules below. This models an
implementation that folds safe early cancellation into its final
terminalization path without silently making `Ready` or `Rebind` a cancel.

If the deadline expires while its batch still has any `Registered` or
`Prepared` fault, the weakly fair kernel watchdog and closure processes can
perform:

```text
Register -> deadline Armed
  -> [Crash -> Fallback -> Ready -> Rebind]
  -> deadline Expired
  -> TimeoutRevoke
  -> Abort each uncommitted closing-epoch fault
  -> Complete each already committed fault
  -> RevokeComplete
```

The bracketed recovery lifecycle is optional: a normally alive pager that
never resolves a fault is subject to the same deadline. If every batched fault
has already crossed `Commit`, the kernel completes them and `DeadlineComplete`
disarms the batch without revoking the scope, even if the pager crashes after
those commits. Committed-fault completion is kernel-owned; the fault deadline
does not become a separate service-liveness lease. Otherwise `TimeoutRevoke`
closes the whole address-space scope and detaches even a live but stalled pager.
`Commit` and `TimeoutRevoke` are atomic competitors on the same `Active` scope
gate: timeout winning prevents the reply; a final commit winning removes that
fault from the uncommitted timeout condition. `TimeoutRevoke` transfers the
remaining work to the scope reverse index and clears the deadline batch.

`Abort` consumes the continuation once, releases any prepared frame, and wakes
the client once with terminal failure. `RevokeComplete` cannot run while a
closing-epoch fault is nonterminal or still owns a prepared frame.

Only these kernel processes are weakly fair:

- scheduler fallback;
- deadline expiration;
- the single closure process, whose branches perform completion, same-page
  satisfaction, stale-fault abort, timeout revocation, early deadline
  cancellation, deadline-batch completion, and revocation completion.

The specification assigns fairness to that closure-process disjunction, not
independently to every branch. The committed bounded graph is monotone and has
no closure branch that can loop forever while starving another. A later model
that introduces retry loops must split or strengthen the relevant fairness
assumptions before retaining these liveness claims.

The pager/environment process is not fair. In particular, the specification
does not assume that a replacement eventually appears or that `Ready`,
`Rebind`, `Adopt`, `PrepareZero`, or `Commit` eventually happens. `pagerAlive`
is not accepted as progress. Every `Registered`, `Prepared`, or `Committed`
fault must eventually become exactly one of `Completed` or `Aborted`, using
only the weak fairness of the kernel deadline and closure processes.

`Register` additionally requires a live bound pager. A hardware fault arriving
while the pager is unavailable is not queued into this scope or its deadline
batch: the first slice must fail that attempt synchronously outside this model.
Queued outage faults are a possible later refinement, not a property checked
here.

## Checked properties

`PagerCserMC.cfg` checks the full reachable graph for:

- token and state-domain type safety;
- single consumption, single wake, and single terminalization of every fault
  continuation;
- every active nonterminal fault belonging to an armed or expired kernel
  deadline batch;
- success only from a committed mapping publication in the same generation;
- at most one mapping publication for the shared slot in each address-space
  generation;
- exact prepared-frame ownership and no terminal retention of a prepared
  frame;
- old pager bindings and old address-space generations being unable to cross
  `Commit`;
- `Ready` preceding `Rebind`, no pager reply before rebind, and no adoption
  after scope closure;
- post-revoke commit exclusion and quiescent closure;
- kernel fallback, deadline expiration or safe early cancellation,
  unconditional registered-fault terminalization, timeout closure, and
  revocation-completion progress under kernel-only weak fairness.

The committed bounded instance has two one-shot fault/thread identifiers, two
frames, one shared page, one possible pager crash/rebind generation, and two
address-space generations (`0` and `1`). With the pinned TLA+ tools 1.8.0 jar,
TLC completes the graph with no error:

```text
17,150 states generated
7,528 distinct states found
0 states left on queue
complete graph depth 17
```

## Run and regenerate

Set `TLA2TOOLS_JAR` to the pinned jar, then run:

```sh
cd specs/cser
java -cp "$TLA2TOOLS_JAR" pcal.trans \
  -nocfg -lineWidth 1000 PagerCser.tla
java -XX:+UseParallelGC -cp "$TLA2TOOLS_JAR" tlc2.TLC \
  -cleanup -config PagerCserMC.cfg PagerCser.tla
```

Edit the PlusCal block rather than the generated transition relation, then
regenerate before checking. A build gate should compare a fresh translation
against the checked-in file, just as it does for `Cser.tla`.

## Model boundary

This is a protocol refinement, not the OSTD pager implementation. It does not
model physical time, lock granularity, allocation outside the scope lock, TLB
shootdown, SMP mapping visibility, real `Task`/`VmSpace` identity, durable pager
state, file paging, COW, swap, eviction, arbitrary task kill, nested scopes, or
fault-ID reuse. `Ready` abstracts the fresh replacement and snapshot handshake;
`PrepareZero` abstracts allocate/zero/revalidate; and `Commit` abstracts PTE
publication plus the continuation-consumption linearization point.

Faults arriving while no pager is bound are deliberately outside the bounded
state graph and must fail fast in the first implementation; the model does not
claim they are queued for a later replacement.

To keep the first finite graph focused, `AddressSpaceChange` waits for any
already committed continuation to reach `Completed` before clearing its slot.
The implementation must still test mutation races around mapping publication
and TLB synchronization; this model does not claim those SMP details are done.
