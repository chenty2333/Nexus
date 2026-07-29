# RFC 0006: CSER core semantic rebaseline

- Status: **Implemented and sealed for the bounded QEMU profile**
- Decision date: 2026-07-29
- Pre-rebaseline checkpoint: `05e68b19b219d0f5288de5438127b5690cd7e50f`
- Recovery references:
  `archive/pre-cser-core-rebaseline-2026-07-29` and
  `pre-cser-core-rebaseline-2026-07-29`
- API stability: **R4 closed; profile 1, journal schema 5, and the standard
  catalog digest are frozen**
- Changes accepted `v0.1.0` claims: **no**

## Decision

Nexus is rebaselined around a portable CSER core. The active engineering
question is no longer how to add another stage to the existing prototype. It
is how to make post-mortem obligations, resource ownership, adoption,
settlement, and retirement one kernel-enforced semantic system that survives
service restart and, under the durable profile, host reboot.

This RFC is the active implementation roadmap. Conflicting stage plans, task
orders, crate boundaries, and compatibility requirements are **Superseded**.
They are not reconciled into a new sequence. Existing checked and observed
results remain historical evidence with their original boundaries.

Breaking Rust APIs, portal APIs, wire schemas, module layouts, and crate
boundaries is allowed. Deleting obsolete implementation is expected. Neither
permission allows accepted evidence, historical status, frozen bytes, negative
results, or prior claims to be rewritten.

The governing rule is:

> Compatibility may be broken; provenance may not. The implementation may be
> replaced; evidence may only be preserved, migrated, or superseded by a new
> separately identified result.

## Supersession and inheritance

The following disposition is normative:

| Source | Superseded as active work | Retained as design or evidence input |
| --- | --- | --- |
| `VISION.md` research gates | Stage numbering, completion order, and use as the current roadmap | research question, claim vocabulary, non-goals, and the exact historical evidence boundaries |
| `REWORK.md` | any interpretation as a live plan | the frozen migration, deletion, and `v0.1.0` evidence ledger |
| RFC 0001 | phase order and the proposed `v0.2.0` implementation shape | identity, same-path evidence, device, concurrency, failure-atomicity, release, and non-claim requirements |
| RFC 0002 | its later-phase task order | the local/global ownership boundary and the rule that signatures or nonces alone do not establish freshness |
| RFC 0003 | tranche order and the current `EffectRegistry` as the final shape | one authoritative obligation model, typed conserved credits, reverse indexes, and reserve/apply/ack ordering |
| RFC 0004 | current bearer layout and portal/API choices as frozen interfaces | non-forgeable one-shot authority, exact replay, bounded backpressure, generation fencing, and no unsafe eviction |
| RFC 0005 | its phase plan as a standalone successor | its adoption obligations, now strengthened by real rebind, a revoke race, repeated crash, durable settlement, and production-transition Loom |

Old RFC text and evidence artifacts are historical records and must not be
edited to imply that later work was already present. In particular, the
pre-rebaseline checkpoint contains a Phase A Rust sliver for RFC 0005
obligations 1 through 4. It does not contain obligations 5 through 7, real
Snapshot/Ready/Rebind, a second crash generation, or an accompanying Loom
harness. This RFC does not relabel that sliver.

An existing task that conflicts with this RFC is closed as `Superseded`, with a
reference to this decision. It is not stretched until its old completion words
appear to fit the new system. A non-conflicting race, workload, trace, model,
receipt, or negative result is an asset to classify and migrate, not a reason
to preserve its old implementation API.

## Thesis

Service death has two different consequences:

```text
service death
    -> future authority is fenced immediately
    -> committed obligations and physical ownership may remain
    -> release occurs only after adoption or verified retirement
```

Process lifetime is therefore not an ownership proof. A queue entry can be
device-visible after the submitting process is gone. A reply can remain owed
after the producer is fenced. A page can remain pinned, an IOVA can remain
reachable, and an IOMMU invalidation can remain incomplete after every
user-space handle has disappeared.

Nexus represents that fact with a first-class post-mortem kernel object. This
RFC calls it a **causal estate**. A causal estate has no user-space execution
authority. It preserves the dead principal's unresolved obligations, resource
charges, recovery coordinates, and evidence requirements until they reach an
allowed disposition.

The slogan "the dead keep owning DMA" has one precise meaning here: the dead
principal's causal estate keeps the DMA debt and resource claims; the dead
incarnation keeps no capability to program the device, publish a reply, or
otherwise act.

## Normative vocabulary

- **Principal**: an authority-bearing service identity.
- **Incarnation**: one executable instance of a principal, fenced by an exact
  binding generation.
- **Causal root**: the stable lineage and accounting root for derived work.
- **Effect**: an operation that may cross an externally visible commit point.
- **Obligation**: a required future disposition created by an effect.
- **Causal estate**: a kernel-owned post-mortem owner for obligations whose
  originating incarnation can no longer act.
- **Resource claim**: typed ownership and accounting for a concrete resource
  such as a queue slot, reply slot, pinned page, DMA mapping, IOVA, or device
  generation.
- **Custodian**: the kernel or adapter that physically holds or controls a
  claimed resource. Custody does not change causal or charge ownership.
- **Charge owner**: the scope or estate against which retained capacity and
  backpressure are accounted.
- **Settlement claim**: a one-shot, generation-fenced authority granted to an
  eligible successor to reconcile an already committed obligation.
- **Retirement evidence**: typed, generation-bound evidence accepted by a
  domain verifier as sufficient to retire one or more exact claims.
- **Reconciliation obligation**: a live object retained when external outcome
  or retirement cannot yet be determined.

The model must not collapse causal owner, charge owner, physical custodian, and
settlement claimant into one `owner` field. They often coincide on the normal
path and deliberately diverge after a crash.

## Required invariants

Every implementation profile must preserve all of the following:

1. **ImmediateAuthorityFence**: once crash or revocation fencing linearizes,
   the old incarnation cannot register, prepare, commit, publish, acknowledge,
   adopt, settle, or release anything.
2. **DeathIsNotRetirement**: principal death, process exit, handle-table
   destruction, portal-session loss, timeout, memory pressure, and age are not
   retirement evidence.
3. **DiscoverablePostMortemOwnership**: every non-retired obligation and claim
   is reachable through one authoritative root/estate index after its principal
   is fenced.
4. **ExplicitSuccession**: a successor receives no old effect implicitly.
   Snapshot, Ready, Rebind, and an exact adopt or settlement-claim transition
   are separate, auditable steps.
5. **SingleAuthority**: one runtime image has exactly one authoritative CSER
   state machine and Registry. Domain adapters, portals, evaluators, and caches
   do not maintain another semantic owner ledger.
6. **SingleDisposition**: each obligation has at most one accepted terminal
   disposition, including across duplicate calls, stale replies, revoke races,
   repeated crashes, and replay.
7. **ClaimConservation**: typed resource claims are moved, split only according
   to their declared class, retained, or released; they are never copied or
   returned before retirement.
8. **EvidenceBeforeReuse**: reset acknowledgement, IRQ drain, IOTLB completion,
   and any domain-specific retirement proof happen before the protected
   hardware generation, IOVA, page, or queue slot can be reused.
9. **FailureAtomicity**: a failed semantic transition either leaves the full
   projection unchanged or leaves a discoverable committed obligation whose
   recovery action is explicit.
10. **BoundedRetention**: unresolved estates consume declared quota and create
    backpressure. Exhaustion rejects before mutation; it never evicts safety
    state by TTL, LRU, process exit, or pressure.
11. **UnrelatedProgress**: pressure in one root or resource class cannot require
    scanning or freezing unrelated roots. Limits and reverse indexes make the
    affected boundary explicit.
12. **ReplayEquivalence**: replay of the durable journal reconstructs the same
    semantic state, claims, gates, high-water marks, and recovery obligations
    as the acknowledged prefix of the original execution.
13. **FreshnessBeforeActivation**: a recovered service or device generation
    becomes active only after the selected profile has rejected stale boot,
    journal, principal, and device generations.

Nexus claims at-most-once authorization and single terminalization. It does not
claim universally exactly-once execution by an external device or provider.
When an external action may have happened, the system reconciles it rather
than executing it again merely because no acknowledgement was observed.

## Orthogonal state

Authority, outcome knowledge, settlement, and physical retirement are separate
state axes. At minimum the core must be able to represent:

```text
AuthorityState = Active | Fenced | Revoked

CommitState = Registered | Prepared | Committed

OutcomeState = Pending | KnownSuccess | KnownFailure | Indeterminate

SettlementState =
    Unclaimed
  | Claimed { claimant_incarnation, claim_generation }
  | ApplyIntentDurable
  | AppliedUnacknowledged
  | Settled

RetirementState = Held | RetirementPending | Retired | Released
```

Not every obligation class uses every state. A class may only narrow this
product, never infer one axis from another.

`Indeterminate` is not merely an error code and is not itself permission to
retain arbitrary resources forever. It materializes a discoverable
reconciliation obligation. The exact resource claims it retains are determined
by the class and are held only while their retirement state requires them. A
known result may coexist with `RetirementPending`; an indeterminate result may
coexist with safely retired physical resources.

## Stable identity and fencing

The durable profile binds every transition to identities equivalent to:

```text
CausalIdentity {
    registry_instance,
    root_id,
    scope_id,
    scope_generation,
    effect_id,
    obligation_id,
    obligation_generation,
}

AuthorityIdentity {
    authority_epoch,
    principal_id,
    principal_incarnation,
    binding_generation,
}

ResourceIdentity {
    class_id,
    class_schema_version,
    resource_id,
    resource_generation,
    device_identity?,
    device_generation?,
}

JournalIdentity {
    journal_instance,
    schema_version,
    sequence,
    predecessor_digest,
}
```

Names may change while the API is unstable, but the distinctions may not.
Generations never wrap or silently reset. Old-boot identities cannot be made
fresh by copying them into a new boot record. Cross-host ownership epochs stay
in the vISA/provider namespace and are never inferred by comparing numeric
Nexus epochs.

## Portable core boundary

The new `cser-core` is the sole production semantic implementation. Its target
shape is `no_std + alloc`, deterministic, and independent of OSTD, a particular
device stack, wall-clock time, threads, filesystem APIs, and durable-storage
APIs.

The core owns:

- identities, generations, state machines, and legal transitions;
- fencing, one-shot gates, adoption, settlement, and terminalization;
- causal-estate, obligation, claim, reverse-index, quota, and credit semantics;
- prepare/apply/ack descriptors and complete before/after projections;
- the versioned journal record schema and deterministic replay algorithm;
- typed errors and idempotent replay projections; and
- normalized transition events consumed by independent conformance tools.

The core does not call external code while mutating authoritative state. It
validates a command and emits a typed plan or apply intent. The driver performs
the external operation without a core semantic lock and returns a typed receipt
to a later acknowledgement transition.

The implementation may physically split pure transition logic, record codecs,
and replay support into small crates if build boundaries require it. Such a
split does not permit more than one semantic implementation or another live
Registry.

## Domain-defined obligation and claim classes

Domains may define obligation and claim classes without defining an alternate
lifecycle. Each class definition has a stable `class_id`, a schema version, its
legal claim set, conservation rule, commit point, allowed settlement actions,
required retirement evidence, and conservative unknown-evidence disposition.

Examples include:

- reply result and one-shot publication;
- service request and response queue slots;
- waiter/waker continuations;
- file or pager publication;
- pinned physical pages;
- VirtIO descriptor and queue ownership;
- DMA mappings and IOVA ownership;
- IRQ drain and device-generation ownership; and
- reset and IOTLB retirement obligations.

The portable interface must not expose any of the following escape hatches:

- an untyped integer credit population shared by incompatible resources;
- an adapter-owned side ledger that can release resources independently;
- a callback that mutates core state directly;
- a generic `quiescent = true`, `cleanup_complete = true`, or equivalent
  boolean accepted as evidence;
- opaque bytes whose class, generation, verifier, and fail-closed behavior are
  unknown during replay; or
- a domain-specific recovery path that bypasses the same gates used by normal
  execution.

A domain verifier converts exact external receipts into typed retirement
evidence. Unsupported or unknown evidence keeps the corresponding claims
retained and applies quota/backpressure. It never defaults to success.

## Adapter, persistence, and oracle boundaries

### Domain and platform adapters

Adapters bind core plans to real mechanisms. They own the exact external commit
point, synchronization edge, device or task coordinate, receipt collection,
and evidence verification for their domain. They do not own causal identity,
fencing policy, obligation state, resource-accounting truth, or terminalization.

The OSTD/kernel adapter owns audited integration with tasks, mappings, IRQ,
VirtIO, IOMMU, reset, and durable storage. User-space supervisors and portals
present requests and receive projections; they never become the authority
database.

### Persistence and freshness providers

The core defines records and replay semantics. A persistence provider supplies
append, ordering, durability barrier, recovery read, and atomic freshness-anchor
operations. A freshness provider supplies a monotonic or otherwise
non-rollbackable anchor appropriate to the deployment profile.

A checksum, signature, nonce, timestamp, or locally incremented counter alone
does not prove anti-rollback freshness. If the configured provider cannot prove
that the selected journal prefix is current, the durable profile fails closed
and keeps affected devices and resources quarantined. Cross-host global owner,
lease, and freshness remain a vISA/provider responsibility.

### Independent oracles

TLA+ models, the independent safe-Rust oracle, trace conformance, property
tests, and external receipt checkers remain separately identifiable evidence
layers. An oracle may share frozen identifiers and trace schemas, but it must
not call `cser-core` transition functions to compute its expected result.

The production implementation and oracle consume the same generated scenarios
or normalized traces and compare projections. Reusing production decisions as
the expected answer is not differential evidence.

## Crash, rebind, adoption, and settlement

Service crash linearizes a binding fence. The transition:

1. advances the binding generation;
2. closes every old-incarnation action gate;
3. leaves already committed effects and non-retired claims discoverable;
4. creates or updates their causal estate;
5. transfers physical custody to the kernel adapter where needed; and
6. schedules bounded recovery work without granting a successor authority.

A replacement follows four explicit steps:

1. `Snapshot` obtains a stable, non-authorizing view of eligible work.
2. `Ready` proves that the fresh incarnation has installed the required local
   state and recovery endpoints.
3. `Rebind` installs the exact new principal incarnation and binding generation.
4. `AdoptEffect` or `ClaimSettlement` consumes a one-shot, exact identity-bound
   authority for one eligible obligation.

`AdoptEffect` applies to work whose domain contract permits a successor to take
over execution. `ClaimSettlement` applies after an irreversible commit, when
the successor may reconcile or publish the retained result but may not pretend
to re-execute the original operation. Combining them into a single ambiguous
`Adopt` operation is forbidden.

Every presented root, effect, obligation, class, digest, authority epoch,
binding generation, resource generation, and publication coordinate is checked
exactly. Wrong or stale input rejects without semantic mutation. No wildcard,
latest-generation shortcut, or silent inheritance is allowed.

### Revoke/adopt race

`RevokeBegin` and a new adopt or settlement claim serialize through one core
gate:

- if revocation wins, no new successor claim is minted; committed obligations
  remain under kernel/estate settlement and honest retention rules;
- if the successor claim wins, revocation observes that exact claim and closure
  cannot erase or duplicate it; and
- stale publication, duplicate claim, and losing-gate retries return canonical
  projections without mutation.

Both winners must be reachable in the independent models and production-source
Loom harnesses. Scheduling one winner deterministically is not race coverage.

### Repeated crash

Settlement is not modeled as an atomic `adopt_and_publish`. It has distinct
crash windows:

```text
claim settlement
    -> durably record publication/reconciliation intent
    -> external apply
    -> collect acknowledgement or evidence
    -> durably settle
```

If the successor crashes in any window, its incarnation and claim generation
are fenced. The causal estate and already durable intent survive. A later
incarnation can receive a new settlement claim only after the core determines
whether it must resume, reconcile, acknowledge, tombstone, or report an
indeterminate outcome. It cannot blindly repeat the external action.

The design must support repeated crashes until a configured generation or
resource limit is reached. Reaching that limit creates explicit backpressure or
operator-required reconciliation; it does not discard the estate or deadlock a
global Registry lock.

## Journal and failure-atomic recovery

The durable journal is versioned from its first implementation. Each record
envelope binds at least:

```text
magic
journal schema version
profile and registry identity
record kind and payload schema version
monotonic sequence
predecessor digest
payload length and digest
record checksum
```

Semantic records bind complete identities and enough before/after information
to detect a conflicting replay. External mutation uses a write-ahead apply
intent that reaches the required durability barrier before the mutation is
allowed. A later acknowledgement binds the exact intent, external generation,
result digest, and evidence.

Recovery accepts only a validated prefix under these rules:

- an incomplete final record may be treated as a torn tail;
- corruption, reordering, a broken predecessor chain, an unknown mandatory
  record, or an invalid record before the tail fails closed;
- replay is idempotent and rebuilding secondary indexes is checked against the
  authoritative records;
- a torn or missing acknowledgement after a durable apply intent reconstructs
  `AppliedUnacknowledged` or an equivalent reconciliation obligation, never an
  automatic retry or release;
- snapshots are optional optimization records and bind the covered journal
  high-water and digest; they are not a second source of truth; and
- format migration is explicit, versioned, crash-testable, and itself journaled.
  Unknown durable state is never silently reset to an empty Registry.

The journal format is not frozen before the reply and DMA milestones. Once
frozen, incompatible evolution requires a new version and an explicit migration
or fail-closed rejection.

## Boot recovery and device tombstones

The durable recovery algorithm runs before ordinary service or device
activation:

1. prevent device bus mastering where possible and establish an IOMMU
   default-deny or equivalent quarantine boundary;
2. establish a fresh boot incarnation and validate the freshness anchor;
3. replay the validated journal prefix into a new in-memory projection;
4. fence every principal incarnation and settlement claim from the prior boot;
5. rebuild and verify root, estate, obligation, claim, quota, and high-water
   indexes;
6. reconstruct every pending external apply and retained tombstone;
7. reconcile each device against its exact hardware and journal generation;
8. require typed reset completion, IRQ drain, IOTLB invalidation completion,
   and generation advance before releasing protected queue, IOVA, page, or DMA
   claims; and
9. permit fresh service Ready/Rebind and device activation only after their
   prerequisites are satisfied.

Late reset, IRQ, completion, or IOTLB acknowledgements carry the old generation
and cannot release a newly allocated resource. An acknowledgement that arrives
after timeout may retire the exact retained tombstone if its identity and
generation still match; it cannot be applied to another generation.

If hardware state cannot be inspected or forced behind a quarantine boundary,
Nexus keeps the device unavailable and the claims charged. That is honest
device tombstone recovery. Reinitializing a driver object or observing a clean
software queue is not evidence that DMA stopped.

## Concurrency boundary

The production core transition functions are the functions exercised by Loom.
A hand-written surrogate that merely resembles them is supplemental and cannot
close this RFC's concurrency gate. Synchronization primitives may be selected
through a small build-time abstraction so the same transition source runs
under Loom and the production environment.

The first required interleaving families are:

- old-incarnation action versus crash fence;
- settlement claim versus `RevokeBegin`;
- successor publication versus stale old publication;
- claim, tombstone, and kernel settlement competing for one gate;
- duplicate and conflicting claim or acknowledgement;
- successor crash before intent, after durable intent, after external apply,
  and before durable settlement;
- reset or IOTLB timeout versus late acknowledgement;
- stale device completion versus generation reuse; and
- journal cut points around intent, apply, acknowledgement, snapshot, and
  migration.

Loom establishes only the stated finite transition interleavings. Real OSTD
locks, IRQ exclusion, memory-order edges, multi-vCPU execution, storage failure,
and hardware drain retain separate evidence gates.

## Implementation milestones

These are **R milestones**, deliberately unrelated to the old Stage numbers.
They are ordered by semantic dependency, not feature count.

### Current implementation status (2026-07-30)

The R6 cutover is sealed for the bounded evidence profile:

- `cser-core` is the portable authoritative state machine, with domain-defined
  reply and DMA obligation/claim profiles, versioned journal records,
  deterministic replay, retained-claim accounting, and freshness coordinates;
- the independent safe-Rust model, property tests, normalized core/oracle
  transition-trace comparisons, and
  production-transition-source Loom cases cover revoke/claim outcomes, stale
  generations, real Snapshot/Ready/Rebind commands, settlement windows, and a
  second successor crash;
- the OSTD default profile installs one recovered `ProductionCoreOwner`, shared
  by the stateless `NXP3` portal, `core-v1` supervisor, reply adapter, and DMA
  adapter; the old live Registry, portal/supervisor glue, and kernel semantic
  mirrors are absent from the production closure;
- the durable profile binds an ATA PIO journal, a separate ATA reply outbox,
  TPM2 NV freshness/catalog state, and a pre-replay VirtIO/VT-d quarantine
  guard; and
- the ordinary dirty-tree production proof has passed four QEMU boots over the
  same raw journal, outbox, and swtpm state: boot-one reply/DMA work runs in
  real service tasks whose exact exit closes production ingress; boot two uses
  a fresh Ready/Rebind task, records a durable apply intent, and crashes that
  successor; boot three reconciles without a duplicate intent; and boot four
  performs a fresh stable Rebind. The host gate observes exact service/binding
  pairs `1/1`, `2/2`, `3/3`, and `4/4`.

Cutover commit `c06e9f43e931ed3f130da6dfcf29452a45406152` passed the clean
four-boot seal. The receipt SHA-256 is
`e0f959e5c4027fb3952384b77de38b6c97e8c5bdd5a9c20f109c515361cf6f1e`;
the release ledger records its exact boundary. R4, R5, and R6 are closed within
that boundary. The QEMU/swtpm path does not establish physical TPM
anti-rollback, physical power-loss recovery, hardware-general DMA quiescence,
crash-persistent PFN/IOVA custody, or resource reuse. Global reset, ISR drain,
and IOTLB observations preserve quarantine; they do not by themselves prove
retirement of old page/IOVA claims.

### R0: preserve and rebaseline

- keep the pre-rebaseline checkpoint reachable by an immutable remote
  reference and record its exact revision;
- preserve the RFC 0005 sliver, trace-conformance work, IRQ Phase A artifacts,
  old model/spec inputs, receipts, manifests, and negative boundaries;
- accept this RFC and classify old tasks as `Superseded`, `Migrate evidence`,
  or `Delete after gate`; and
- do not claim any new runtime capability.

### R1: portable core foundation

- create the new portable core and make it the only candidate production
  semantic state machine;
- implement identities, estates, domain-defined obligation/claim classes,
  typed credits, reverse indexes, gates, exact projections, and bounded quotas;
- implement the versioned journal codec, pure replay algorithm, and crash-cut
  model for external intents;
- establish a new independent formal and safe-Rust oracle family; and
- add property and differential tests for invariants and exact rejection.

Exit requires no OSTD, device, portal, or storage dependency in the pure core;
no alternate live Registry; and no class escape hatch forbidden above.

### R2: real post-commit reply slice

- execute the normal request through the production Registry and reply path;
- crash a real service incarnation after backend commit and before reply;
- fence it and create a kernel-owned causal estate;
- create a fresh task/incarnation and perform real Snapshot, Ready, Rebind, and
  `ClaimSettlement` transitions;
- publish or tombstone through the same one-shot gate;
- cover both revoke/claim winners, stale reply, wrong identity, duplicate
  receipt, and credit/backpressure paths;
- crash the successor at every settlement window and recover with another
  incarnation; and
- run Loom over the actual core transition source, plus independent model,
  property, normalized differential-trace, and one-vCPU OSTD evidence. The
  retained pre-rebaseline TLC trace-conformance crate remains historical
  evidence and is not relabeled as a new formal family.

Exit requires exact source-bound receipts and no Registry-free closure trigger
standing in for the replacement service.

### R3: real DMA/IOMMU slice

- carry one stable root and obligation lineage through queue reservation,
  descriptor preparation, the real queue-publication commit, completion, IRQ
  drain, reset, IOTLB invalidation, and resource release;
- retain queue slots, pinned pages, DMA mappings, IOVAs, and device-generation
  claims after service death;
- exercise timeout, reset failure, late/stale acknowledgement, retry,
  generation advance, tombstone pressure, and unrelated-root progress;
- prove by typed receipt that reset and IOTLB completion precede page/IOVA reuse;
  and
- run the same core, independent oracle, production-source Loom, and exact
  runtime evidence layers used by the reply slice.

An abstract adapter, no-device probe, polling-only software marker, or
separate-boot component log cannot satisfy the real commit and retirement
requirements by itself.

### R4: API freeze gate

Core API and durable schema review begins only after R2 and R3 both pass without:

- adapter-owned semantic state;
- direct core-state mutation by a domain;
- untyped cleanup or quiescence booleans;
- duplicated identities or credits in a side ledger;
- a reply-only or DMA-only recovery special case;
- a Registry-free evaluator substituted for the normal path; or
- a requirement to live dual-write old and new Registries.

Passing this gate freezes the first CSER core API and journal profile. It does
not imply production readiness or reboot recovery.

### R5: persistent reboot recovery

- provide a real durable journal provider and declared durability barriers;
- inject failure at every journal append, barrier, snapshot, migration, and
  external apply/ack boundary;
- recover valid prefixes and reject corrupt, reordered, and rolled-back state;
- exercise torn writes and repeated reboot during recovery;
- quarantine devices before replay and recover retained device tombstones;
- establish boot, principal, journal, and device freshness through the declared
  provider; and
- show cross-reboot backpressure, later reconciliation, and exact resource
  release after retirement evidence.

Exit requires cold-boot runtime receipts. A host-process restart, an in-memory
Registry reconstruction, or a signed but rollbackable file is insufficient.

### R6: production cutover and cleanup

- replace the production Registry with the new core in one cutover;
- replace the portal and supervisor interfaces with versioned vNext interfaces;
- remove old live Registry, session-local semantic caches, compatibility glue,
  and production semantic mirrors;
- retain independent oracles, evidence parsers, immutable wire corpora, and
  historical receipts outside the live authority path; and
- run the complete cold verification and exact-revision CI contract.

Old and new implementations may exist during development in mutually exclusive
build or test configurations. A runtime may never dual-write, merge, or choose
between two authoritative Registries. There is no long-lived compatibility
mode after cutover.

## API and wire policy

No current Rust type, crate boundary, portal operation, or in-memory layout is
preserved solely for compatibility. The development API may change whenever a
change strengthens the rebaseline or removes duplicated semantics.

Published identifiers and frozen bytes are never silently reinterpreted. A
new semantic contract uses a new protocol/schema identifier. Old wire decoders
may remain in offline conformance and migration tooling, but the production
path does not keep a legacy authority adapter alive merely to accept them.

Persistent state has a stricter rule than session wire: either an explicit,
tested migration converts an old journal version into a new version, or boot
fails closed with the affected estates and devices quarantined. "Start empty"
is not an upgrade strategy.

## Deletion gates

Old live semantics and compatibility code may be deleted after all relevant
conditions below are true:

1. The exact pre-rebaseline revision is recoverable from an immutable remote
   reference, and its status as a partial local successor is recorded.
2. Every unique contract, race seed, fault cell, trace, workload, receipt,
   hardware log, source digest, negative result, and non-claim has been
   classified as migrated or historically retained.
3. The reply and DMA slices pass against the same new production core without
   a forbidden escape hatch.
4. Cargo metadata and repository search prove that no production adapter,
   portal, supervisor, kernel path, or release workflow depends on the old live
   Registry or compatibility API.
5. The replacement has one authoritative Registry and no dual-write path.
6. Independent model, property, production-source Loom, normalized
   core/oracle trace comparison, retained historical trace-conformance,
   focused runtime, and full cold verification gates pass at the exact source
   revision.
7. Durable-state deletion additionally waits for R5 recovery, corruption,
   rollback, and device-quarantine tests.
8. The release manifest records every removed runtime surface, every retained
   historical artifact, and the exact remaining non-claims.

Git history is sufficient for ordinary implementation source after these
gates. Git history alone is not sufficient for evidence that otherwise exists
only in ignored files, generated receipts, external logs, mutable branches, or
unrecorded environment state.

## Evidence and claim discipline

This RFC changes direction, not inherited evidence status. The implementation
status above identifies current source facts; every unsealed exit condition and
the remaining milestone text still denote requirements, not accepted
capability.

Evidence layers remain separate:

- declarative specification and bounded model checking;
- independent executable oracle and property tests;
- production-transition-source Loom;
- source mapping and static contract checks;
- one-vCPU and later multi-vCPU OSTD observation;
- real IRQ/device/reset/IOTLB observation;
- durable reboot, storage-failure, and freshness observation; and
- release/source/provenance verification.

No layer inherits a stronger status from an adjacent layer. A same-boot trace
does not establish reboot recovery. QEMU does not establish hardware-general
quiescence. A valid journal record does not establish anti-rollback freshness.
A model state called `Retired` does not establish that a real device stopped
DMA.

The accepted `v0.1.0` tag, artifacts, DOI, receipts, and claims remain
immutable. The `05e68b1` checkpoint is a distinct pre-rebaseline development
checkpoint and may not inherit `v0.1.0` acceptance or future rebaseline claims.

## Stop and pivot conditions

The rebaseline stops and records a negative boundary if any of the following is
required for progress:

- granting a dead or stale incarnation authority so cleanup can complete;
- releasing a physical claim based only on process death, timeout, pressure,
  software queue state, or an untyped adapter assertion;
- allowing a domain to keep a second authoritative ledger;
- treating `Indeterminate` as terminal closure while required claims disappear;
- replaying an uncertain external action without reconciliation;
- silently resetting or accepting rolled-back durable state;
- enabling a device before quarantine, generation reconciliation, and required
  retirement evidence;
- making reply and DMA semantics share only names while retaining separate
  lifecycle implementations; or
- preserving a compatibility surface that forces permanent dual authority.

If bounded retention prevents useful progress, the response is to make quota,
reconciliation, operator recovery, and resource replacement explicit. It is
not to weaken evidence-before-reuse.

## Non-goals

This RFC does not claim:

- transparent rollback of committed external effects;
- universally exactly-once device or provider execution;
- migration of device-internal state;
- cross-host owner, lease, consensus, or global freshness inside Nexus;
- malicious rollback resistance without an appropriate trusted provider;
- general Linux compatibility, a production filesystem/network stack, or all
  OSTD behavior;
- lock freedom, wait freedom, arbitrary SMP liveness, or hardware-general DMA
  quiescence from finite models or QEMU alone; or
- preservation of any obsolete Nexus API, stage number, module layout, or task
  merely because it existed before this decision.

## Acceptance summary

The CSER Core Rebaseline is complete only when one source-bound evidence chain
establishes all of the following together:

- immediate stale-incarnation fencing with retained post-mortem ownership;
- domain-defined obligations and resource claims under one portable core;
- real Snapshot/Ready/Rebind and exact effect adoption or settlement claim;
- both revoke/claim race winners and repeated successor crash recovery;
- the same production transition source under Loom and real adapters;
- reply publication and real DMA/IOMMU retirement without escape hatches;
- a versioned, failure-atomic journal with torn-write recovery;
- boot-time device quarantine, device tombstone recovery, and typed
  reset/IRQ/IOTLB evidence before resource reuse;
- boot, principal, journal, and device freshness across restart;
- bounded backpressure and unrelated-root progress while estates remain live;
- a single production Registry after an atomic cutover; and
- immutable historical evidence plus exact new claims and non-claims.

The exact source-bound evidence chain above is sealed by the production cutover
release ledger. Completion is limited to its declared QEMU/swtpm/ATA profile;
API cleanup, a passing unit suite, or a renamed Registry alone would not have
satisfied this acceptance contract.
