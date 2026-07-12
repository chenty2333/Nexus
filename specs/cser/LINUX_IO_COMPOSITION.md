# Seven-domain Linux I/O CSER composition

`LinuxIoCompositionCser.tla` is the additive bounded successor that composes
the filesystem and network runtime branches with the existing system-wide
CSER domains. It does not modify or retroactively widen the frozen
`CompositionCser`, `RuntimeFsCser`, or `RuntimeNetCser` receipts.

This successor fixes one root authority, seven independently represented
domain bindings, nine effects, eight typed credit classes, the filesystem and
network publication boundaries, VirtIO reset/IOTLB tombstone recovery, exact
ordered closure receipts, and side-effect-free stale-input rejection in one
state machine.

## Fixed causal graph

The bounded graph has ten nodes including the root and nine immutable parent
edges:

```text
Root
|-- FsSyscall                 Personality / Control
|   |-- PagerMap              Pager / Memory
|   |   `-- SchedulerAction   Scheduler / Scheduling
|   `-- FsOperation           Filesystem / Filesystem
|       `-- BlockRequest      VirtIo / Dma
`-- NetSyscall                Personality / Control
    `-- NetOperation          Network / Network
        |-- ReadinessWait     Readiness / Readiness
        `-- BufferLease       Network / Buffer
```

Control has capacity two because the root owns both syscall effects.
Scheduling, Memory, Filesystem, Dma, Network, Readiness, and Buffer each have
capacity one. Derivation transfers exactly one credit of the effect's type
from the root ledger. Terminalization returns that same typed credit.
`TypedCreditConservation` checks every class independently; an unrelated free
credit cannot compensate for a missing DMA or buffer credit.

The formal and implementation names for the three abbreviated I/O effects are
equivalent:

| TLA+ effect | Rust/OSTD effect |
| --- | --- |
| `FsOperation` | `FsOp` |
| `BlockRequest` | `BlockReq` |
| `NetOperation` | `NetOp` |

The graph is a finite model-checking instance, not an implementation
restriction. It exercises two root branches, two internal forks, and chains up
to four effects below the root. It does not prove arbitrary DAGs, repeated
effect identifiers, nested root scopes, or dynamic graph growth.

## Root gate and independent generations

There is one root scope and one root authority epoch. `RevokeBegin` is the
single root linearization point: it freezes the exact effect and participating
domain cohorts, snapshots commit counts, closes the derivation and commit gate,
advances the authority epoch, and creates one pending closure-receipt slot for
each participating domain. No domain-local scope can mint root authority or
complete root revocation independently.

The model keeps the following fencing dimensions separate:

| Fence | Advanced by | Meaning |
| --- | --- | --- |
| root authority epoch | `RevokeBegin` | closes derivation and commit across all domains |
| per-domain binding epoch | crash of that domain | fences only the failed service binding |
| address-space generation | pager publication | fences stale mapping envelopes |
| inode generation | filesystem publication | fences stale inode envelopes |
| device generation | successful reset acknowledgement | fences stale block/device envelopes |
| socket generation | network publication | fences stale socket envelopes |
| source generation | readiness publication | fences stale readiness envelopes |

`DeriveEffect` and every commit require an active root scope, an open root
gate, the current authority epoch, a bound target domain, and the current
target binding. Generation-bearing effects additionally require the matching
address-space, inode, device, socket, or source generation.

`DomainBindingIsolation` checks that a crash changes exactly one binding
entry and none of the authority or object generations. `GenerationIsolation`
checks each object-publication transition independently. These are distinct
from the timeout-receipt revision described below.

## Filesystem and network publication

The filesystem branch distinguishes four irreversible observations:

1. `PagerMap` publishes the PTE and synchronized TLB state and advances the
   address-space generation.
2. `FsOperation` publishes `HoleXY` into the modeled inode and advances the
   inode generation.
3. `BlockRequest` publishes the block request and retains the DMA credit until
   completion or reset/IOTLB closure.
4. `FsSyscall` freezes `PwriteOK`; a later fair kernel step publishes the
   one-shot guest result.

The network branch likewise separates `NetCommit`, `ReadyCommit`, and guest
publication. `NetCommit` atomically publishes the socket-generation envelope,
`Ping4` payload, and buffer lease. `ReadyCommit` consumes that exact immutable
envelope and freezes its socket, source, and payload identity. The network
syscall can freeze `LoopbackOK` only after the operation and readiness wait
have completed; a later fair kernel transition publishes it once.

An active peer may consume a queued buffer. If revocation wins first, the
kernel-owned closure path consumes or closes it without fabricating a guest
reply. `PublicationReceiptImmutability` prevents any published network,
readiness, or syscall result from being rewritten.

## Crash, recovery, and adoption

The state machine retains seven independent domain bindings. A service crash
advances only the selected binding and freezes that domain's exact
uncommitted recovery cohort. Recovery follows:

```text
Crash -> Fallback -> Snapshot -> Ready -> Rebind -> explicit Adopt
```

Snapshot and ready validation cover the binding plus address-space, inode,
device, socket, and source generations. Only an uncommitted member of the
captured cohort can be adopted into the new binding. Committed effects remain
kernel-owned and cannot be adopted.

The finite scenario quotient, described below, gives explicit crash/adopt
witnesses for the two newly composed service domains, Filesystem and Network.
The seven-domain binding and recovery invariants still quantify over every
domain; this model does not claim a separate crash witness for all seven.

## DMA tombstones and receipts

A published block request cannot be rolled back. Root closure must instead
complete it, reset it, or preserve exact ownership in a tombstone. A reset
timeout retains the block identity and DMA credit. A reset acknowledgement,
not timeout retry, advances the device generation and records an indeterminate
block outcome. An IOTLB timeout retains the invalidating mapping and DMA
credit. Retry supersedes the old timeout receipt, removes the tombstone, and
allows kernel closure to continue. `Revoked` requires no tombstone and no
retained DMA ownership.

Timeout and closure receipts share one global monotone sequence. Closure
receipts follow the implementation order:

```text
Scheduler, Pager, VirtIo, Filesystem, Readiness, Network, Personality
```

Each required domain produces exactly one receipt containing the closing
authority epoch, its current binding, its domain revision, and, for VirtIO,
the device generation. A timed-out VirtIO receipt cannot be closed until the
tombstone has been retried and the fresh revision is recorded.

`TimeoutReceiptRevisionDiscipline` is intentionally narrow. It constrains the
formal timeout-receipt supersession quotient only: a revision change occurs in
`Closing`, while a tombstone exists, and increments exactly the VirtIO
revision by one without changing peer revisions. It is not a general
seven-domain mutation counter, and it does not require authority, binding, or
resource generations to remain unchanged during that transition. Exact
mutation-to-revision validation is stronger Rust/OSTD evidence, not a result
claimed by this TLA+ quotient. `TimeoutHonesty` additionally requires every
retried timeout receipt revision to be older than the current VirtIO domain
revision.

## Stale-input audit boundary

The reject-enabled safety graph audits these ten stale-input classes in a
fixed order:

```text
AddressSpace, Inode, Socket, Source, Device, Binding, Authority,
TimeoutReceipt, ClosureReceipt, CompletionReplay
```

`RejectProbe` first constructs the real enabling history for each class:
object generations advance, Filesystem or Network crashes, root revocation
closes the gate, IOTLB timeout retry supersedes an old revision, a closure
receipt is issued, and an effect terminalizes. Every abstract reject event is
then guarded by `StaleEnabled`. `RejectSideEffectFreedom` checks the complete
semantic state projection and permits only the audit bookkeeping fields
`rejectKinds` and `rejectIndex` to change.

These are predicate-gated abstract audit events. A reject kind implicitly
stands for an old envelope or receipt; the TLA+ state does not carry a
separate attempted-token payload. The exact attempted-token validators in the
Rust and OSTD successors are therefore stronger evidence. This model checks
that a genuinely enabled abstract stale input is side-effect free; it does not
claim byte-level validator equivalence.

## Explicit state-space quotient

An initial model that enabled all feature combinations in one graph exceeded
9.24 million distinct states with 4.59 million states still queued and was
honestly stopped. The checked model uses five explicit nondeterministic
scenario partitions over the same state machine and the same universal
invariants:

| Scenario | Preserved behavior |
| --- | --- |
| `DeriveRace` | root revocation may win between any two deterministic graph derivations |
| `Core` | mixed filesystem/network publication, suppression, readiness, guest publication, and complete closure |
| `NewDomainCrash` | Filesystem or Network crash, rebind, explicit adoption, and peer-binding isolation |
| `DmaTimeout` | reset plus IOTLB timeout, fresh-revision retry, and tombstone-free closure |
| `RejectProbe` | prerequisite-guided stale authority, binding, generation, receipt, and replay rejection |

Derivation order is deterministic only as a state-space reduction;
`DeriveRace` preserves the revoke-versus-derivation cut at every edge. The
other partitions retain the interleavings relevant to their named evidence.
The result is an exhaustive check of the union of these five bounded
partitions, not of the abandoned all-feature Cartesian product. In
particular, it does not establish arbitrary combinations such as every domain
crashing amid every publication and both DMA timeout stages.

## Checked properties

Both configurations check 20 state invariants:

- types, gate discipline, the fixed graph, causal identity, retained parent
  records, legal effect lifecycles, and typed-credit conservation;
- filesystem, network, readiness, and guest-publication discipline;
- crash isolation, exact recovery, the frozen closure cohort, no post-revoke
  commit or derivation, exact receipts, honest timeouts, single
  terminalization, and quiescent closure.

They also check ten action properties: immutable causal edges, derive and
commit gates, binding and object-generation isolation, timeout-receipt
revision discipline, explicit adoption, reject side-effect freedom, immutable
publication receipts, and the global receipt sequence.

The action configuration adds two temporal property formulas:

```text
ConditionalFallbackProgress
ConditionalKernelClosureProgress
```

TLC expands them into three temporal branches because fallback progress is
quantified separately over Filesystem and Network. Thus the exact statement
is two property formulas and three TLC branches. Weak fairness applies only
to kernel-owned steps. Environment-owned snapshot, ready, rebind, adopt,
reset acknowledgement, timeout, and retry actions intentionally have no
liveness claim. Kernel closure is conditional on the block request already
being terminal, no tombstone remaining, and DMA being absent or released.

`check.sh` additionally requires ten independent reachability witnesses:

1. all seven domains close the complete nine-effect graph with exact
   filesystem, network, readiness, guest, and receipt publications;
2. root revocation suppresses both I/O branches before publication;
3. filesystem publication remains visible while the network branch aborts;
4. network publication remains visible while the filesystem branch aborts;
5. Filesystem crash/adopt advances no peer binding;
6. Network crash/adopt covers both the operation and buffer lease and advances
   no peer binding;
7. readiness publication wins before root revocation without fabricating a
   guest reply;
8. root revocation wins after immutable network publication but before
   readiness publication;
9. reset and IOTLB tombstones retain DMA through fresh-receipt closure; and
10. all ten stale envelope, receipt, and replay audit events become genuinely
    enabled and remain side-effect free.

## Checked result

The checked-in PlusCal translation was generated with `pcal.trans 1.12` and
checked with TLC `2026.07.09.134028` in pinned image
`nexus/cser-dev:aa2f1d8f6c5100f7`.

The reject-enabled safety/action-property configuration
`LinuxIoCompositionCserSafetyMC.cfg` completed with no error:

```text
3,723,455 states generated
1,225,367 distinct states found
0 states left on queue
complete graph depth 55
45 seconds
```

The liveness configuration `LinuxIoCompositionCserMC.cfg` completed with no
error:

```text
3,656,517 states generated
1,207,917 distinct states found
0 states left on queue
complete graph depth 46
3 temporal branches
4 minutes 48 seconds
```

Deadlock checking is disabled because quiescent `Revoked` states and
environment-dependent recovery states may stutter legally. The ten required
reachability runs are separate counterexample searches against the safety
configuration; a pass means TLC found the required witness that violates its
corresponding `...Absent` coverage invariant.

Run only this family inside the pinned development container with:

```sh
TLA2TOOLS_JAR=/opt/tla2tools/tla2tools.jar \
  ./specs/cser/check.sh LinuxIoCompositionCser
```

When editing the PlusCal block, regenerate it with the pinned tool before
checking:

```sh
cd specs/cser
java -cp "$TLA2TOOLS_JAR" pcal.trans -nocfg -lineWidth 10000 \
  LinuxIoCompositionCser.tla
```

## Model boundary

This is bounded protocol evidence for one root, one authority transition, one
effect of each non-Control type, two Control effects, at most one service
crash, one publication per resource generation, one reset and IOTLB timeout,
and the five explicit scenario partitions. It does not prove:

- arbitrary graphs, workloads, failures, retries, generations, or receipt
  counts;
- all-domain crash reachability, crash combinations, or all-feature
  interleavings outside the five partitions;
- rollback of an already published inode, device, socket, readiness, or guest
  effect;
- an on-disk filesystem, full Linux VFS/socket ABI, TCP/IP, VirtIO-net, NIC,
  external-packet, durable external-effect, or power-loss protocol;
- SMP ordering, lock freedom, asymptotic work proportionality, throughput, or
  latency;
- concrete IOMMU invalidation, hardware quiescence, or exact Rust/OSTD
  validator equivalence; or
- general mutation-revision matching outside the modeled VirtIO timeout
  receipt quotient.

Those implementation, concurrency, scale, performance, and external-device
claims require their own evidence. This formal successor supplies the bounded
seven-domain composition map without changing the narrower facts frozen in
its predecessors.
