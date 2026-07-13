# Production-identity CSER successor

Status: **prospective RFC-0001 formal successor; bounded Checked semantics
only**.

`ProductionIdentityCser.tla` asks whether one workload-created CSER identity can
remain intact across a block-backed filesystem-read shape, domain-local service
recovery, the device commit/revoke race, same-effect reset and IOMMU tombstone
retry, guest-reply publication, and leaf-first root closure.

The result in this directory does not report an OSTD implementation, a real
filesystem read, same-boot VirtIO or IOMMU activity, an interrupt, SMP execution,
hardware quiescence, or a `v0.2.0` release. The 2-CPU and 4-CPU configurations
use abstract actor identities only. They state the ownership and ordering facts
that later implementation evidence would have to refine.

## Relationship to the frozen predecessors

This model is additive. It does not edit or reinterpret `Cser`,
`RuntimeFsCser`, `CompositionCser`, or `LinuxIoCompositionCser`.

The earlier composition successors use fixed bounded cohorts and separate
domain envelopes. This successor instead starts with no effects and
dynamically derives one complete workload tree inside one modeled registry:

```text
Root
`-- PersonalitySyscall               Personality / Control
    `-- FilesystemRead                Filesystem / FilesystemCredit
        `-- BlockRequest              VirtIo / QueueSlot
            |-- DmaQueueOwnerA        VirtIo / DmaOwner
            |-- DmaQueueOwnerB        VirtIo / DmaOwner
            `-- DmaRequestOwner       VirtIo / DmaOwner
```

The fixed topology is a model-checking bound, not a claim that production CSER
supports only this tree. The model checks dynamic instantiation of those six
records; it does not check arbitrary trees, nested scopes, multiple roots, or
multi-parent effects.

## Registry and identity boundary

Every accepted derivation atomically installs:

- `RegistryA` as the registry instance;
- immutable root authority epoch zero;
- effect generation one;
- the fixed immutable causal parent;
- the effect's origin and current domain-binding epochs;
- workload provenance (`createdByWorkload=TRUE`);
- the applicable device session and generation for device effects;
- one typed shared-ledger reservation.

There is no evaluation-only replacement cohort. `effectsAtClose` may contain
only records whose workload derivation transition ran in the same state graph.
`CausalIdentityImmutability` prevents parent, registry, effect generation,
authority, origin binding, device session, or workload provenance from changing
after derivation.

The one shared typed ledger has capacities:

| Credit class | Capacity | Owner effects |
| --- | ---: | --- |
| `Control` | 1 | `PersonalitySyscall` |
| `FilesystemCredit` | 1 | `FilesystemRead` |
| `QueueSlot` | 1 | `BlockRequest` |
| `DmaOwner` | 3 | the two queue owners and one request owner |

Each effect's credit moves through `None`, `Held`, `Committed`, `Retained`, and
`Returned`. `TypedCreditConservation` checks each class independently in every
reachable state. A reset or IOMMU timeout changes all four device-side credits
to `Retained`; it does not increase `freeCredits`.

## Registry-native bindings and recovery

`bindingEpoch`, `domainPhase`, `recoveryCohort`, `snapshotBinding`, and
`snapshotCohort` are one root-registry binding table indexed by Personality,
Filesystem, and VirtIo. They are not per-scenario side ledgers.

The bounded crash scenario stops after preparing `FilesystemRead` and follows:

```text
Crash -> Snapshot -> Ready -> Rebind -> explicit Adopt
```

`Crash` advances only the Filesystem binding from zero to one. The frozen
recovery cohort contains the one uncommitted filesystem effect. Rebind alone
does not change it; `Adopt` changes only its current binding. Registry instance,
effect generation, origin binding, parent, authority, and typed credit remain
unchanged. Personality and VirtIo bindings remain zero.

Only one filesystem crash is present in the committed finite bound. The model
does not check repeated crashes, crashes in every domain, durable recovery
state, or a concrete service supervisor.

## Commit and root revocation

All six effects reach `Prepared` before the modeled device batch commit.
`DeviceCommit` is the conservative `avail.idx` publication abstraction. Under
one root gate it checks every authority and domain binding, commits all six
causal obligations, freezes device generation zero, and records the abstract
service CPU.

In the `CommitRevokeRace` partition, `DeviceCommit` and `RevokeBegin` are both
enabled from the same prepared state:

- if `RevokeBegin` wins, all six effects remain uncommitted and kernel closure
  aborts them leaf-first with no guest reply;
- if `DeviceCommit` wins, revocation inherits the committed block/DMA and guest
  reply obligations. Later closure completes rather than rolls them back.

`PostRevokeCommitExclusion` checks that every effect with
`commitAtClose[e]=0` remains uncommitted after the gate closes.

## Device, reset, and IOMMU semantics

The device path deliberately keeps effect identity separate from the mutable
device generation:

- the effect generation, registry instance, parents, and `SessionA` never
  change;
- device commit records generation zero;
- a reset timeout retains the same block and DMA-owner effects and credits;
- reset retry consumes the existing tombstone;
- reset acknowledgement alone advances the current device envelope to
  generation one and produces the bounded `Eio`/indeterminate backend result;
- an IOMMU timeout retains the same owners again;
- IOMMU retry and acknowledgement release the mapping boundary;
- only after release may the three DMA owner effects, block request,
  filesystem read, and personality syscall terminalize in child-first order.

The model separately reaches a normal `Data` completion. Backend completion and
the one guest reply are distinct transitions. The reply is published only after
the three DMA effects, block effect, and filesystem effect have completed. A
reset path publishes one `Eio` reply rather than pretending that an already
committed device request was uncommitted.

`RejectProbe` presents two deliberately invalid inputs:

1. a `RegistryB` identity to the `RegistryA` root;
2. the generation-zero completion after reset acknowledgement advanced the same
   effect's device envelope to generation one.

`RejectSideEffectFreedom` checks that these probes change only the audit set and
last-actor diagnostic fields, not the full semantic projection.

## Leaf-first closure and receipts

`RevokeBegin` freezes the workload-created records, live cohort, committed
cohort, typed-credit obligation, and all three participating domains. An
uncommitted effect can abort only after every instantiated child is terminal.
Committed effects use the explicit device/IOMMU, filesystem, and guest-reply
completion path.

Each terminal transition receives a monotone sequence. If a parent is terminal,
every child must already be terminal with a smaller sequence.

Domain receipts are also child-first:

```text
VirtIo -> Filesystem -> Personality
```

Each receipt captures its domain binding; VirtIo also captures the current
device generation. `RevokeComplete` requires all frozen effects terminal, all
domain receipts closed, the exact closure-step count, every typed credit at
capacity, no tombstone, released-or-absent DMA, and one guest reply whenever the
device commit occurred.

## Abstract 2-CPU and 4-CPU actors

`CpuCount` is either two or four. The finite model assigns:

- workload derivation/preparation/device commit to `ServiceCpu=0`;
- crash, revoke, retry, terminalization, receipt, and closure work to
  `KernelCpu=1`;
- device completion, reset acknowledgement, IOMMU acknowledgement, and stale
  completion rejection to `IrqCpu=CpuCount-1`.

The 2-CPU witness therefore has two distinct actor CPUs. The 4-CPU witness has
three distinct actor CPUs. `ActorBoundarySafety` checks that each recorded
boundary is owned by the selected abstract role and that all actors belong to
the configured CPU set.

These fields do **not** model OSTD `SpinLock`, local interrupt masking,
release/acquire operations, interrupt delivery, cross-CPU memory visibility,
TLB shootdown, scheduling fairness, lock freedom, or SMP liveness. They are
formal obligations and reachability witnesses for a later refinement, not real
SMP evidence.

## Checked properties

Both complete safety configurations check:

- types and scope/gate cohesion;
- workload-only registry identity and immutable ancestry;
- registry-native domain bindings and domain-local crash isolation;
- effect and credit lifecycle cohesion;
- per-type shared-ledger conservation;
- explicit recovery/adoption discipline;
- post-revoke first-commit exclusion;
- one-shot guest-reply discipline;
- same-effect/session device identity and honest tombstones;
- leaf-first terminalization and child-first domain receipts;
- cross-registry/generation reject prerequisites;
- abstract actor ownership;
- single terminalization and quiescent closure.

The action configuration additionally checks:

- causal identity immutability;
- workload/registry-only derivation;
- the complete commit gate;
- one-domain-only binding advancement;
- explicit adoption without identity replacement;
- reset-only device-generation advancement;
- terminalization only after live children are gone;
- reject side-effect freedom.

The progress configuration checks five temporal branches produced by:

- conditional kernel closure once no environment/device action remains needed;
- conditional final revoke completion;
- conditional receipt progress for each of the three domains.

Only the generated PlusCal `Kernel` process is weakly fair. Service readiness,
crash, device completion, timeouts, retry, and invalid-input presentation are
environment actions and receive no fairness assumption.

## Required reachability gates

`check.sh ProductionIdentityCser` requires expected counterexamples to seven
deliberately false invariants. The actor witness is checked at both CPU counts,
for eight witness traversals total:

| Witness | Scenario | Result |
| --- | --- | --- |
| workload-created normal read and closure | `Normal` | reachable |
| filesystem crash/rebind/adopt identity | `CrashRecovery` | reachable |
| device commit wins the shared gate | `CommitRevokeRace` | reachable |
| root revoke wins the shared gate | `CommitRevokeRace` | reachable |
| reset plus IOMMU same-effect retry | `DeviceTimeout` | reachable |
| foreign-registry and stale-generation rejects | `RejectProbe` | reachable |
| abstract actor separation, two CPUs | `ActorRace` | reachable |
| abstract actor separation, four CPUs | `ActorRace` | reachable |

These searches deliberately stop at the expected invariant violation. With
multiple TLC workers, the generated/distinct count at the first discovered
witness depends on worker scheduling, so those partial counts are not treated
as stable results and are not added to the complete totals below.

## Complete TLC results

With the repository-pinned `tla2tools.jar` 1.8.0 and eight workers, the complete
bounded graphs are:

| Configuration | Result | Generated | Distinct | Depth | Temporal branches |
| --- | --- | ---: | ---: | ---: | ---: |
| `ProductionIdentityCserSafetyMC.cfg` | pass, zero queued | 4,793 | 3,396 | 33 | none |
| `ProductionIdentityCserSmp4SafetyMC.cfg` | pass, zero queued | 4,793 | 3,396 | 33 | none |
| `ProductionIdentityCserActionMC.cfg` | pass, zero queued | 4,793 | 3,396 | 33 | action properties |
| `ProductionIdentityCserProgressMC.cfg` | pass, zero queued | 3,356 | 2,670 | 32 | 5 |

The equal two-/four-CPU safety counts are expected. CPU roles are fixed abstract
values; the four-CPU configuration changes their identities and checks the
three-role witness without adding a hardware scheduler or memory model.

Run the independent prospective gate through the repository front door with:

```sh
./x research production-identity
```

It checks the committed PlusCal translation, the four exact complete graph
populations, and all eight ordered reachability witnesses. Its receipt and logs
are written to `target/research/production-identity/`, outside the accepted
`v0.1.0` manifest and bundle population.

Inside the pinned development container, the lower-level focused command is:

```sh
TLA2TOOLS_JAR=/opt/tla2tools/tla2tools.jar \
  ./specs/cser/check.sh ProductionIdentityCser
```

After editing the PlusCal block, regenerate its checked-in translation:

```sh
cd specs/cser
java -cp "$TLA2TOOLS_JAR" pcal.trans -nocfg -lineWidth 10000 \
  ProductionIdentityCser.tla
```

## Exact finite boundary

The committed instance has:

- one root and one authority transition;
- one registry instance plus one deliberately foreign presented registry;
- three service domains and one binding advance in Filesystem only;
- six dynamically instantiated effects in one fixed tree;
- one effect generation and one immutable device session;
- four typed credit classes and six total credit units;
- one atomic six-effect device batch commit;
- one normal completion or one reset-generation advance;
- at most one reset timeout/retry and one IOMMU timeout/retry;
- one guest reply;
- three child-first domain receipts;
- six fixed scenario partitions;
- abstract actor identities for either two or four CPUs.

It does not establish a production registry implementation, fallible allocation
atomicity, a real lock hierarchy, IRQ safety, SMP memory ordering, an actual
block-backed read, same-boot DMA, physical-device quiescence, arbitrary graphs,
nested/multiple roots, repeated failures, asymptotic work, performance,
durability, or a stronger CSER contribution decision. Those remain prospective
RFC-0001 implementation and evaluation gates.
