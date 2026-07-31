# RFC 0007: CSER composite effect custody

- Status: **Accepted; profile-2 software and bounded QEMU protocol pass on the
  current dirty worktree; clean release seal and physical hardware open**
- Decision date: 2026-07-30
- Evidence update: 2026-07-31
- Predecessor: [RFC 0006](0006-cser-core-semantic-rebaseline.md)
- Frozen predecessor coordinates: **core profile 1, journal schema 5,
  standard catalog v4, and projection v5**
- New coordinates: **core profile 2, journal schema 6, standard catalog v5,
  projection v6, and recovery snapshot v2**
- Deferred, non-blocking evidence format: **canonical normalized differential
  trace v2**
- Changes accepted `v0.1.0` or RFC 0006 evidence: **no**

## Decision

Nexus will represent the logical result and physical-resource custody of one
escaped operation as components of one durable `EffectId`.

At the RFC 0007 decision baseline, the profile-1 production reply and DMA
paths shared one authoritative `cser-core` runtime and one Registry, but
created separate effects under separate roots. Core profile 1 also gave each
estate exactly one domain, obligation, lifecycle policy, and claim population.
That implementation proved that one authoritative core could manage reply and
DMA estates. It did not prove that the reply/output obligation and
queue/PFN/IOVA custody of one operation were conserved by one effect identity.

Core profile 2 closes that gap. An effect contains a catalog-bound set of
domain-local components. The effect owns common identity, authority, fencing,
escape, recovery, and final release. Each component owns its own obligation,
commit, outcome, settlement, retirement, and claims. Components may discharge
independently, but neither an adapter nor a component may erase, replace, or
independently release the parent effect.

The governing statement is:

> After closed-world rollback has failed, one escaped effect conserves both its
> logical result obligations and its physical reuse restrictions. Executor
> death transfers or removes authority; it does not create a custody gap.

This is an incompatible semantic revision. It advances the core API, catalog,
projection, recovery snapshot, and journal coordinates. Schema-5 state is never
interpreted as if it contained composite-effect relationships that it did not
record. A future canonical normalized differential trace remains useful
evidence, but it is not a completion condition for this rebaseline.

## Relationship to RFC 0006

RFC 0006 remains unchanged and sealed for its stated bounded QEMU profile. Its
implementation receipts, release ledger, source coordinates, and non-claims
remain true at their original revisions. This RFC supersedes profile 1 only as
the active development target; it does not relabel profile-1 evidence as
profile-2 evidence.

The following RFC 0006 principles are inherited without weakening:

- immediate stale-incarnation fencing;
- death is not retirement;
- one authoritative core and Registry;
- typed claim conservation and evidence before reuse;
- explicit Snapshot, Ready, Rebind, adoption, and settlement;
- deterministic, freshness-bound journal recovery;
- boot-time device quarantine;
- no live dual-write or compatibility authority; and
- strict separation between model, QEMU, and physical-hardware claims.

The new requirement is stronger: heterogeneous obligations belonging to one
escaped operation must be discoverable and enforced under the same
`EffectId`, not merely under the same runtime image or Registry.

## Evidence boundary at adoption

The profile-1 production slice uses one reply effect and another DMA effect.
Its retained four-boot receipt reports `shared_runtime=true`,
`production_registry=single`, retained page/IOVA claims, and
`resource_reuse_authorized=false`. The focused DMA receipt reports
`core_resource_reuse=true` and `physical_address_reuse=false`.

Those receipts remain evidence for:

- one recovered portable-core owner shared by the reply and DMA adapters;
- reply settlement across a second service crash;
- logical claim retention and generation fencing;
- QEMU-observed reset, IRQ drain, and IOTLB commands; and
- continued boot quarantine while physical custody is not established.

They are not evidence for:

- one operation-created `EffectId` spanning reply and DMA;
- atomic fencing of a composite effect's component actions;
- component-local partial discharge under one effect;
- reconstruction of allocator ownership after reboot;
- exact old-PFN or old-IOVA retirement; or
- cross-reboot authorization to reuse a physical address.

## Current evidence status

The profile-2 implementation now has a passing but intentionally nonsealable
evidence chain. The current combined receipt is
`kernel/nexus-ostd/artifacts/cser-production/combined-proof.txt`; its companion
digest is
`5c1da57d103006935cf7f7090bbf5ae721ac0c88070e9d852ac70b4a4a7c56e6`.
The receipt says `NONSEALABLE`, `nonsealable_reason=source-tree-dirty`, and
`seal_requested=false`. It records base revision
`7c82d0c9f26d77a630faeaeb28e139c36beb5319`, which is not an exact name for
the dirty source and must not be presented as the final implementation
revision.

The current software evidence establishes:

- the independent oracle and model-side Loom cover the full `6 x 11 = 66`
  product of modeled reply and DMA partial states, including a second crash in
  every cell;
- core and the independent oracle have equal normalized public projections after
  33 acknowledged durable prefixes, including component order, claim units,
  tombstones, resource generations, permit lifecycle, and high-water state;
- every one of those 33 prefixes is recovered twice from the same journal and
  trusted anchor, and both recoveries match the live core and oracle
  projections;
- a separate recovered-engine probe advances through Checkpoint, Snapshot,
  Ready, Rebind, and adoption, then reissues and activates each pending permit,
  checking the retained catalog, retirement, and provider-contract digests
  without treating a cached live bearer as recovered state;
- schema 6/profile 2, catalog v5, projection v6, and recovery snapshot v2 pass
  their format, sensitivity, replay, race, stale-input, and failure-atomicity
  tests; and
- the static production cutover gate finds one profile-2 Registry and no live
  profile-1 fallback, merge, or dual-write path.

The current QEMU evidence separately establishes:

- a negative boot in which the trusted TPM candidate selects the pinned
  schema-5 journal, pre-replay quarantine completes, and recovery returns typed
  `MigrationRequired` before current-catalog binding, semantic replay, inferred
  pairing, production Registry publication, or device activation;
- four fresh QEMU processes using the same schema-6 journal, swtpm state,
  outbox, and RAM backing file, with strictly increasing freshness and
  service/binding generations;
- one operation effect `EffectId(root=50433, sequence=1)` whose reply outbox
  uses component `1` and whose queue/DMA custody uses component `2`;
- first and second exact task death, parent fencing, fresh
  Snapshot/Ready/Rebind, durable reply apply-intent recovery without a second
  intent, DMA partial retirement, and stable repeated recovery; and
- persistent-arena generation `1 -> 2` reuse at the same guest PFN base
  `196608`, emulated IOVA base `1073741824`, and RAM backing-file offset
  `805306368`, followed by failure-atomic rejection of old-generation core
  evidence.

That last observation is a QEMU protocol result. It proves reuse of a reserved
guest-physical arena coordinate, an emulated IOMMU coordinate, and its backing
file offset across QEMU process restarts. It does **not** prove identity or
reuse of the same host-physical PFN, an observed old-domain hardware unmap,
physical DMA transaction drain, real late IRQ/ACK or DMA-write isolation,
physical power-loss durability, or physical TPM anti-rollback. Those remain
the separate C4/H-01..H-06 hardware gate.

## Normative vocabulary

- **Composite effect**: one operation identified by one durable `EffectId` and
  containing a catalog-bound set of heterogeneous components.
- **Component**: a stable, effect-local unit identified by `ComponentId`. It
  owns one domain-defined obligation and its lifecycle axes.
- **Component obligation**: the domain-defined future disposition required of
  one component, such as publishing one reply or reconciling one DMA request.
- **Component-local claim**: a typed logical or physical resource claim owned
  by exactly one component while remaining causally and financially charged to
  the parent effect.
- **Effect authority**: the common generation-fenced authority under which any
  principal-originated component action must execute.
- **Settlement authority**: a component-scoped, one-shot authority to resolve
  a committed logical obligation. It is not physical custody.
- **Physical custodian**: the kernel or provider that can prevent, observe, or
  retire device and allocator access to a physical resource.
- **Partial discharge**: a state in which at least one component obligation or
  claim has reached its allowed terminal disposition while another remains
  live.
- **Claim tombstone**: compact durable state retaining the old resource
  identity, generation, evidence digest, and high-water after capacity has
  been discharged.
- **Reuse permit**: a one-shot, generation-bound authorization to activate a
  new resource generation after the exact prior generation is locally safe.
  It binds the successor claim, catalog, old-generation retirement digest, and
  the kernel/provider contract which gives the opaque resource physical
  meaning.
- **Persistent DMA arena**: a boot-reserved fixed guest-coordinate arena whose
  CSER claim generations can be reconstructed before general allocation or
  device activation.

`RootId` remains a lineage, accounting, and recovery-index coordinate. A
shared root alone is not the composite effect identity and does not satisfy
this RFC.

## Authoritative object model

Profile 2 has one authoritative `EffectRecord` per `EffectId`:

```text
EffectRecord {
    effect: EffectId,
    composite_kind: CompositeKindId,
    causal_owner: PrincipalIncarnation,
    charge_owner: ChargeAccountId,
    authority: AuthorityState,
    authority_epoch: u64,
    escape: EscapeState,
    components: Map<ComponentId, ComponentRecord>,
}

ComponentRecord {
    component: ComponentId,
    domain: DomainId,
    obligation: ObligationKindId,
    policy: ObligationPolicy,
    commit: CommitState,
    outcome: OutcomeState,
    settlement: SettlementState,
    retirement: RetirementState,
    claims: Map<ClaimId, ClaimRecord>,
}

ClaimRecord {
    component: ComponentId,
    domain: DomainId,
    kind: ClaimKindId,
    resource: ResourceId,
    resource_generation: ResourceGeneration,
    physical_coordinate: PhysicalCoordinate?,
    custodian: CustodianId,
    charge_owner: ChargeAccountId,
    state: ClaimState,
    evidence_digest: Digest?,
}
```

The names and exact Rust layout may differ. Executor authority belongs to the
parent effect. Component settlement claims and physical claim custody remain
component-local; that distinction is normative.

An effect is not implemented as a synthetic `COMPOSITE_DOMAIN`. Reply and DMA
retain their own domain catalogs, verifier identities, commit points, and
retirement rules. A composite catalog rule declares one exact ordered component
product and binds each component to one existing domain obligation. The
referenced obligation and claim rules define component-local policy; generic
profile-2 invariants define parent terminality and resource reuse. Adapters
cannot install arbitrary callbacks that decide either result.

### Topology

`RegisterCompositeEffect` atomically creates the parent identity and every
component in the catalog's exact ordered product. Successful registration is
the topology seal; there is no production `Building` state. Claims may be
enrolled only in a component and claim class admitted by the referenced
obligation. No component may later be added, removed, renumbered, or
reclassified.

This rule ensures that a reply adapter cannot discover after queue commit that
it was given a different effect, and a DMA adapter cannot synthesize a sibling
effect after the logical operation has already escaped.

### Common authority and fencing

All principal-originated component commands bind:

```text
(EffectId, authority_epoch, PrincipalIncarnation, binding_generation)
```

One parent fence linearization:

1. advances the effect authority epoch;
2. rejects every old-incarnation action in every component;
3. revokes every component settlement token and the parent execution authority
   held by that incarnation;
4. retains every committed obligation, durable intent, claim, and accepted
   evidence; and
5. transfers physical custody only through an explicit kernel/provider
   transition.

A device interrupt, completion, reset acknowledgement, or IOTLB receipt may
arrive after the principal fence. Such input is evidence, not principal
authority. It can mutate core state only through the configured kernel
verifier and only for the exact effect, component, claim, device generation,
and evidence challenge.

### Separate ownership roles

The model must not collapse these roles:

- the parent effect's causal owner;
- the account charged for retained capacity;
- the principal currently authorized to execute or settle one component; and
- the kernel/provider physically holding one claim.

After executor death, a fresh task may receive reply settlement authority while
DMA claims remain in kernel custody. Moving reply authority never implicitly
moves, retires, or releases queue/PFN/IOVA claims.

## Component-local lifecycle

Every component has independent, monotonic lifecycle axes:

```text
CommitState = Registered | Prepared | Committed

OutcomeState = Pending | KnownSuccess | KnownFailure | Indeterminate

SettlementState =
    NotApplicable
  | Unclaimed
  | Claimed { claimant, claim_generation }
  | ApplyIntentDurable
  | AppliedUnacknowledged
  | Settled

RetirementState = Held | RetirementPending | Retired
```

One component crossing `Committed` does not infer another component's commit
state. Reply acknowledgement does not infer DMA retirement. Device reset does
not infer reply failure or success. `Indeterminate` is a terminal logical
outcome only where the catalog allows it; it is never physical retirement
evidence.

The parent effect has a derived escape and completion state:

```text
EscapeState = Unescaped | Escaped | Closing | Retired | Released
```

- `Unescaped`: no component has crossed an irreversible commit point.
- `Escaped`: at least one component has crossed such a point.
- `Closing`: authority is fenced or revoked and at least one component remains
  non-terminal or retains a live claim.
- `Retired`: every required component disposition is terminal and every live
  claim has been discharged, while compact generation tombstones may remain.
- `Released`: the parent record has passed its release gate and only global
  high-water/provenance state remains.

`Retired` and `Released` are parent states. A component may become terminal and
its resources may become locally reusable before the parent reaches either
state.

## Claim conservation and partial discharge

A claim belongs to exactly one `(EffectId, ComponentId, ClaimId)` and one
resource generation. For a given generation it is created once, moved between
declared custodians without copying, and discharged once.

```text
ClaimState =
    Reserved
  | Active
  | Quarantined
  | RetirementPending
  | Discharged
  | Tombstone
```

The live claim population may shrink as exact claims are discharged. The
parent effect and non-terminal components remain discoverable. Discharging a
claim releases its conserved capacity only after its domain rule and the active
production profile's custody boundary are satisfied; it does not delete the old
identity or generation high-water.

For the initial reply-plus-DMA composite profile, the intended progression is
permitted but not forced:

```text
queue claim
    -> device reset + completion/IRQ drain
    -> queue discharged

PFN and IOVA claims
    -> domain evidence + provider-defined local release condition
    -> PFN and IOVA discharged

reply claim
    -> durable settlement intent + exact publication reconciliation
    -> reply discharged
```

Any ordering consistent with each component's domain rules and the generic core
invariants is legal. In particular, a retired DMA resource generation may be
reused while the reply component remains unsettled. Conversely, a settled reply
does not authorize DMA-resource reuse.

The portable catalog does not by itself claim an independent, generic allocator
relinquishment receipt. In the current QEMU profile, pinned-page discharge is
scoped to the fixed arena's provider contract: the pages remain globally
withheld and a new CSER lease reuses the same slots. A general allocator-return
claim requires the separate hardware/provider evidence described below.

The core projection must expose both component and parent status. Reporting
only a parent boolean such as `complete` or only aggregate retained units is
insufficient differential or production evidence.

## Resource-local reuse predicate

Reuse is authorized for one core resource generation, not for an entire effect.
For resource `r` and old generation `g`, profile 2 may durably reserve generation
`g + 1` only if:

```text
CoreReuseAllowed(r, g, g + 1) :=
    ExactClaim(r, g).state in { Discharged, Tombstone }
    and RequiredEvidenceAccepted(ExactClaim(r, g))
    and NoLiveClaimForResourceId(r)
    and ResourceHighWater(r) == g
    and RecoveryCheckpointComplete
    and ScopeNotQuarantined(r)
    and ExactParentAuthorityAccepted
    and FreshnessAccepted(boot, journal, registry, device)
```

Generation arithmetic never wraps or skips. The portable core's reverse index
prevents two live claims for the same opaque `ResourceId`; it does not infer
whether two different identifiers alias one physical extent. The current QEMU
profile avoids that stronger problem by using one fixed, globally withheld
arena layout. Physical alias exclusion is a separate hardware gate.

The durable reservation and its linear `ReusePermit` jointly bind:

```text
effect and component
exact successor claim through the component claim index
resource, expected old generation, and exact next generation
actor, binding generation, and parent authority epoch
one-shot nonce
boot, journal, Registry, device, and catalog coordinates
catalog-bound digest of all accepted old-generation retirement evidence
kernel/provider reuse-contract digest for the concrete resource interpretation
```

The permit is consumed once by reserve/activate. Failed activation leaves the
new generation reserved or quarantined; it never reactivates the old
generation. An old-generation command or evidence value cannot mutate or
authorize generation `g + 1`.

## Revoke, adoption, and settlement

Execution adoption and fencing are effect-wide. Settlement authority is
explicit and component-local.

- A wholly uncommitted composite effect may be adopted only when every
  component remains before commit, each obligation permits adoption, and the
  successor holds the current parent authority epoch.
- A committed logical component is never converted back to ordinary execution
  adoption. A fresh successor requests a one-shot settlement claim.
- A committed DMA component normally remains in kernel/provider custody and is
  reconciled by typed device evidence; service adoption does not imply device
  custody.
- A root revoke and effect adoption race on one exact expected authority epoch.
  If revoke wins, the stale adoption fails without mutation. If adoption wins,
  revoke accounts for the newly installed parent authority and all components;
  it may not discard their obligations.

Independent models and production-source Loom must reach both race winners.
Serial tests that schedule only one winner do not close this requirement.

## First and repeated executor crash

The first executor crash fences the parent effect once and leaves all component
state discoverable. A successor performs Snapshot, Ready, Rebind, then either
effect-wide adoption of a wholly uncommitted composite or an exact
component-local settlement claim. The recovery snapshot carries the single
parent identity plus every component projection and retained claim record.

Settlement is not an atomic `adopt_and_publish` action:

```text
claim settlement
    -> durable component apply intent
    -> external apply or reconciliation
    -> exact acknowledgement/evidence
    -> durable component settlement
```

If the successor crashes again:

1. the parent authority epoch advances again;
2. every token held by the second incarnation becomes stale;
3. durable intents and accepted external facts remain unchanged;
4. already discharged DMA claims do not resurrect;
5. still-live DMA claims remain charged and quarantined;
6. the reply component resumes at its exact durable window; and
7. another fresh successor may act only after a new Ready/Rebind and exact
   claim transition.

This behavior is required at every reachable partial-discharge state, including
before and after each reply intent/apply/ack boundary and before and after each
queue, PFN, and IOVA retirement boundary. Recovery never repeats an external
apply merely because the acknowledgement was lost.

## Core API profile 2

Profile 2 is an incompatible public semantic contract. At minimum it adds:

- stable `ComponentId` and `CompositeKindId` identities;
- atomic composite registration and topology sealing;
- effect and component projections;
- component-bound command, evidence, settlement, and recovery coordinates;
- component-local claim indexes and parent-effect reverse indexes;
- claim discharge and tombstone transitions;
- exact opaque-resource generation and reverse-index coordinates;
- resource-local reuse planning and one-shot permit consumption; and
- parent release derived from component and claim terminality.

Profile 1 APIs may remain in offline conformance binaries or mutually exclusive
test builds. No profile-1 adapter, Registry, decoder, or state machine may be a
live authority in the profile-2 production image.

## Catalog, projection, snapshot, and trace versions

The standard catalog advances from v4 to v5. Its digest preimage includes:

- composite kind identifiers;
- each composite kind's exact ordered component product;
- each component's `ComponentId`, domain, and obligation;
- the referenced obligation policy, adoption rule, claim cardinalities, and
  receipt bindings;
- the referenced claim's credit, scope, evidence prerequisites, verifier, and
  receipt-schema bindings; and
- the generic profile-2 interpretation selected by catalog version 5.

Catalog v5 does not encode cross-component dependency graphs, physical overlap
providers, allocator leases, or hardware topology. Parent release, resource
generation, retained-record, and QEMU dedicated-arena rules are generic profile-2
or production-profile invariants, not hidden catalog fields.

The deterministic projection digest advances from v5 to v6 and includes the
parent effect, ordered component projections, component claim populations,
partial-discharge state, durable pending-reuse reservations, retained retired
claim/resource records, and resource generation high-water indexes. Omitting a
component or hashing only aggregate totals is invalid.

Projection-v6 coverage is frozen by a canonical golden vector and
field-sensitivity vectors which hold revision and journal head fixed while
changing parent, component, claim, or pending-reuse fields. Replay evidence
compares two independent recoveries under the same journal prefix and trusted
anchor. A reboot which advances freshness is expected to change the digest;
freshness-sensitive projections must not be compared as if they were the same
boot state.

The recovery snapshot advances from v1 to v2. A v2 snapshot contains one
parent record with ordered components, not a list whose entries are paired by
the consumer. It binds the v5 catalog digest and journal schema 6 head.

Applied `TransitionReceipt` values carry a `NORMALIZED_TRACE_VERSION=2` metadata
coordinate plus the root, parent effect, component, and claim coordinates that
the current command can identify. This carrier is not a canonical normalized
differential trace: it has no frozen codec for attempted commands and typed
rejections, no ordered affected set for root-wide or multi-component commands,
and no profile-1/v2 decoder contract. Defining that artifact remains deferred
and does not gate this RFC's release labels. Existing profile-1 traces remain
historical evidence and are never relabeled as profile-2 traces.

## Journal schema 6

Schema 6 uses a new magic and version coordinate, `CSERJR6\0` and `6`. Every
record continues to bind the complete durability/freshness envelope required by
RFC 0006 and additionally binds `core_api_profile=2`, the profile-2 catalog,
and parent/component coordinates.

The command grammar must encode complete identities for:

- atomic composite registration and topology sealing;
- component prepare and commit;
- effect-wide fence and revoke;
- effect-wide adoption and component-local settlement;
- component-local claim enrollment and discharge;
- external apply intent and acknowledgement;
- DMA-claim quarantine and typed retirement evidence;
- reuse-permit issue and consumption;
- parent retirement and release.

Recovery reconstructs the parent/component graph directly from acknowledged
schema-6 records and validates all forward and reverse indexes. It does not
join independently recovered objects after replay.

### Schema-5 fail-closed rule

Schema 5 records one domain and obligation per estate. The current reply and DMA
records have different `EffectId` and `RootId` values and contain no durable
association manifest proving that a particular pair came from one operation.
Consequently, when an inspected trusted TPM candidate tip selects a non-empty
schema-5 journal as the deployment's active durable authority, profile-2 boot
must reject it before semantic replay as `MigrationRequired`,
`UnsupportedVersion { 5 }`, or an equivalently typed fail-closed result. The
candidate is not bound to the current profile-2 catalog, device and
dedicated-arena guards remain quarantined, and no schema-6 Registry is
published.

No migration or recovery tool may infer pairing from:

- the current reply and DMA root constants;
- equal or adjacent effect sequence numbers;
- record timestamps or journal adjacency;
- matching boot, principal, Registry, or device generations;
- current hard-coded resource identifiers;
- equal charge accounts or custodians; or
- knowledge of the present test workload.

Those properties are not a durable causal association and may collide across
operations or future versions.

Profile 2 defines no automatic schema-5 migration, drain, importer, pairing, or
Registry-rollover protocol. An operator may continue running the exact frozen
profile-1 deployment and settle it under its own rules, or separately establish
that the old deployment is no longer an active authority before provisioning a
new profile-2 Registry. Those are operational actions outside this state
machine, not a schema-6 transition and not evidence that two old estates were
one effect.

If a trusted anchor still selects schema-5 state, cutover remains blocked and
the affected device and dedicated arena remain quarantined. Starting schema 6
with an empty Registry while ignoring that active legacy authority is forbidden.

An immutable schema-5 journal retained only as an evidence artifact and not
selected by any boot or persistence provider is not live state and is not
migrated. It remains byte-for-byte historical evidence. The fail-closed rule
applies to schema-5 state selected as the active durable authority for the
deployment being upgraded.

An offline diagnostic may inspect a copied legacy journal under the exact
frozen profile-1 implementation. It may not emit an activatable schema-6 estate,
merge two estates into one composite effect, issue reuse permits, or become the
live profile-2 Registry. Current schema-5 journals have no automatic migration
path of any kind.

The pinned QEMU schema-5 fixture contains exactly one committed reply estate.
It proves typed rejection of selected non-empty legacy state, quarantine
retention, and absence of current-catalog binding or Registry publication. It
is not a two-estate pairing experiment. Non-inference from roots, sequence
adjacency, timestamp-like values, shared epochs, resources, or charge accounts
is established by the host pairing-collision corpus and arbitrary-suffix
property.

## Persistent DMA arena and physical coordinates

Journaling a numeric PFN or IOVA is not ownership. A physical-hardware
cross-reboot reuse claim requires a provider that can exclude the old extent
from all competing allocation and device reachability before ordinary boot
activation.

The current QEMU profile is scoped to a narrower dedicated-arena protocol. It
uses a fixed three-page guest-physical range which the global frame allocator
withholds before serving ordinary allocations, and a fixed emulated IOVA
layout. The layout digest is bound as the DMA component's durable commit
operation. Four fresh QEMU processes use the same schema-6 journal, swtpm state,
and RAM backing object; guest physical byte `N` therefore refers to the same
backing-file offset `N` in each process.

For this profile, QEMU process termination is the old device/IOMMU transaction
boundary. The next process starts with new emulated device and IOMMU state,
fences bus mastering, resets the VirtIO device, drains its ISR state, and
completes the global IOTLB barrier before journal replay or device activation.
This is not an observation of an exact unmap from a persistent old IOMMU domain.

The reconstructed QEMU custody tuple binds:

```text
effect / component / claim
fixed QEMU BDF and device scope
journal-bound arena layout digest
arena slot, guest PFN extent, and emulated IOVA range
core resource generation
device generation
journal and freshness coordinates
```

The core accepts the configured reset, ISR-drain, and global-IOTLB evidence for
the exact old claim, terminalizes its dedicated-arena generation, then consumes
one resource-local permit to activate the same guest coordinates at generation
`g + 1`. The arena pages are never returned to the general allocator; reuse
means a new CSER lease over the same withheld guest slots.

This QEMU path has no generic physical-overlap provider receipt, persistent
IOMMU-domain identity, allocator epoch, hardware DMA transaction-drain receipt,
or real late-device-event injector. Those belong to the separate physical
hardware gate. Raw equality of guest PFN, emulated IOVA, or backing offset is
never promoted into a host-physical ownership claim.

## Production cutover

One real agent operation creates one composite effect before either reply
publication or queue commit. Production ingress obtains a handle equivalent to:

```text
CompositeEffectHandle {
    effect: EffectId,
    authority_epoch,
    reply_component: ComponentId,
    dma_component: ComponentId,
    catalog_digest,
}
```

The reply outbox records the parent effect and reply component. Queue
submission, DMA leases, completion evidence, and IOMMU retirement record the
same parent effect and the DMA component. Neither adapter may substitute a
root-local effect, allocate another effect on demand, or maintain a side
terminalization ledger.

Production switches once:

1. profile-2 core, persistence, adapters, and cold-recovery gates pass in a
   mutually exclusive development build;
2. no trusted recovery anchor selects schema-5 state as the active authority;
3. ingress is fenced and the profile-1 Registry is stopped;
4. one schema-6 Registry is created or recovered;
5. reply, DMA, portal, supervisor, boot recovery, and arena providers bind to
   that Registry; and
6. profile-1 production modules and fallback selection are removed from the
   live dependency closure.

There is no live dual-write, shadow comparison Registry, read fallback, merge,
or runtime profile selector. Offline trace comparison and historical decoders
remain independent evidence tools only.

## Independent oracle and property evidence

The safe-Rust oracle implements the profile-2 transition relation without
calling `cser-core` transition, projection, reuse, or recovery functions. It
may share only frozen identifiers and input schemas.

Generated command/state sequences must cover at least:

- effect registration and topology sealing;
- each component commit before and after the parent fence;
- both revoke/effect-adopt winners;
- reply settlement while DMA claims remain live;
- DMA retirement and reuse while reply remains unsettled;
- every legal partial-discharge ordering;
- stale and duplicate reply acknowledgements;
- modeled late IRQ, reset, completion, and IOTLB evidence values;
- reuse-permit issue/consume races and stale-generation rejection;
- second crash at every reachable partial state;
- journal cuts around every durable intent, evidence, discharge, and permit
  record; and
- unrelated-effect progress while one composite effect remains quarantined.

Core and oracle projections must match after every acknowledged transition and
every recovered prefix, including component ordering, live claim units,
tombstones, permits, and high-water indexes.

## Production-source Loom evidence

Loom exercises the same profile-2 transition source used by production. The
minimum interleaving families are:

- parent fence versus reply prepare/commit;
- parent fence versus queue prepare/commit;
- revoke versus effect-wide adoption, with both winners;
- successor claim versus second parent fence;
- reply apply/ack versus DMA retirement evidence;
- queue discharge versus late completion or IRQ acknowledgement;
- PFN/IOVA discharge versus reset and IOTLB timeout/late acknowledgement;
- reuse-permit issue versus old-generation evidence;
- permit consumption versus a conflicting reservation;
- old-generation IRQ/ACK versus generation-plus-one activation; and
- second crash before intent, after durable intent, after external apply, after
  acknowledgement, and after each claim discharge.

Each test asserts failure atomicity, one terminal disposition per component,
claim conservation, no old-authority action, no duplicate external apply, no
duplicate live core-resource generation, and unrelated-effect progress. A
surrogate state machine is supplemental only.

## Evidence layers for DMA reuse

The following claims are intentionally separate.

### Portable model and host property evidence

This layer establishes state-machine invariants, deterministic replay, exact
generation checks, and fail-closed schema behavior. It proves no device or
physical-address fact.

### QEMU protocol evidence

The QEMU gate uses the same schema-6 journal, freshness state, swtpm state, RAM
backing object, and journal-bound fixed arena layout across fresh QEMU
processes. It must observe:

- one real operation whose reply and DMA components share one parent effect;
- the fixed guest PFN extent withheld before general allocation;
- pre-replay bus-master fencing, VirtIO reset, ISR drain, and global IOTLB
  completion in each successor process;
- generation `g` terminalized in the core before a reuse permit is consumed;
- the same guest PFN, emulated IOVA, and backing-file offset mapped and used at
  generation `g + 1`;
- an old-generation core evidence request rejected without changing revision,
  projection, or the generation-plus-one owner; and
- the declared four-process reply/DMA partial-discharge and second-crash
  sequence.

Passing this gate establishes dedicated guest-arena lease reuse under a QEMU
process-restart protocol. Process termination supplies the old device/IOMMU
boundary; the gate does not claim an observed exact old-domain unmap, a real
late IRQ/ACK or DMA write into the new owner, reuse of the same host physical
page, hardware-general DMA quiescence, physical power-loss durability, or
physical TPM anti-rollback.

### Physical-hardware PFN/IOVA evidence

The hardware gate records the exact machine, firmware, IOMMU mode, requester
identity, arena PFNs, IOVA extents, device/reset method, interrupt mode, and
power/reboot procedure. It must show that those exact physical PFNs and IOVAs:

- are reserved before the general allocator on recovery;
- remain inaccessible to the quarantined device and other requester domains;
- receive the required reset, drain, unmap, and invalidation evidence;
- are relinquished by the old lease;
- are assigned at generation plus one to a declared new owner; and
- cannot be modified by an injected or naturally late old-generation event.

Only this layer authorizes a claim of physical cross-reboot PFN/IOVA reuse for
the tested hardware profile. Results are device-, IOMMU-, firmware-, and
failure-mode-specific. One machine never establishes hardware-general DMA
quiescence.

## Milestones

### C0: specification and independent model

Current status: **accepted on dirty-tree software evidence; clean seal
pending**.

- accept this RFC and the profile-2 acceptance matrix;
- define the composite catalog and stable oracle/core projection mapping;
- implement the independent oracle and generated crash/partial-discharge
  scenarios; and
- record the exact prior-art and evidence non-claims.

Exit requires model/oracle agreement on all required reachable cases. It does
not authorize a production or physical-resource claim.

### C1: portable profile-2 core and schema 6

Current status: **accepted on dirty-tree software evidence; clean seal
pending**.

- implement the parent/component state model and reverse indexes;
- implement resource-local discharge, tombstones, and reuse permits;
- freeze catalog v5, projection v6, recovery snapshot v2, and journal schema 6;
- test journal cuts around every profile-2 durable boundary;
- prove candidate-selected schema-5 input fails closed before current-catalog
  binding and semantic replay; and
- pass production-source Loom.

Exit requires no component or adapter escape hatch and no automatic schema-5
pairing.

### C2: one-effect production reply and DMA

Current status: **accepted on dirty-tree static and QEMU evidence; clean seal
pending**.

- create one effect from one real operation;
- bind reply outbox and queue/DMA work to separate components of that effect;
- execute real task death, fence, Snapshot/Ready/Rebind, settlement, device
  reconciliation, partial discharge, and a second crash; and
- atomically cut production to the one profile-2 Registry.

Exit requires source mapping and receipts that print the same `EffectId` for
both components, plus proof that no profile-1 live authority or dual-write path
remains.

### C3: persistent arena and QEMU generation reuse

Current status: **accepted for the bounded QEMU protocol on dirty-tree
evidence; clean seal pending**.

- reserve and recover exact guest PFN/IOVA leases before normal allocation;
- terminalize dedicated-arena generation `g` under the configured typed
  evidence and QEMU process boundary;
- activate the same coordinates at generation `g + 1`;
- reject an old-generation core evidence request without mutating the new owner;
  and
- preserve the declared reply/DMA partial-discharge and second-crash sequence
  across four fresh QEMU processes.

Exit authorizes only the QEMU protocol claim.

### C4: physical-hardware closure

Current status: **open**.

- repeat the exact-address generation-reuse experiment on a declared physical
  device and IOMMU profile;
- include reboot and power-failure cases supported by the claimed profile;
- retain raw allocator, IOMMU, IRQ, reset, and freshness receipts; and
- publish the exact hardware-scoped claim and remaining non-claims.

Full physical PFN/IOVA reuse is unaccepted until C4 passes. Lack of available
hardware is an evidence blocker, not permission to upgrade the QEMU claim.

## Required invariants

Profile 2 preserves RFC 0006 invariants and adds:

1. **OneEffectIdentity**: one operation's declared reply and DMA components
   have exactly one parent `EffectId` from registration through release.
2. **TopologyIntegrity**: the sealed component manifest is immutable and
   catalog-valid before any component can escape.
3. **EffectWideFence**: one fence linearization invalidates all old-principal
   component actions and settlement tokens.
4. **ComponentAxisIndependence**: no component infers another component's
   commit, outcome, settlement, or retirement state without an explicit core
   transition.
5. **ComponentClaimConservation**: every claim remains attached to exactly one
   parent and component until its one allowed discharge.
6. **NoCustodyGap**: moving execution or settlement authority never leaves a
   physical claim without a declared kernel/provider custodian.
7. **MonotonicPartialDischarge**: accepted discharge never resurrects a live
   old-generation claim, including after repeated crash and replay.
8. **ResourceLocalReuse**: an effect's unrelated live obligation neither
   authorizes nor unnecessarily blocks reuse of an independently safe resource.
9. **NoGenerationAlias**: old and new generations of one core `ResourceId`
   cannot both be live. The QEMU profile additionally fixes non-overlapping
   dedicated arena slots; physical alias exclusion remains a hardware gate.
10. **LateEvidenceIsolation**: old-generation evidence cannot mutate or release
    a new generation.
11. **LegacyNonInference**: schema-5 estates are never paired into a composite
    effect without a causal association that schema 5 did not record.
12. **SingleProfileAuthority**: a production runtime has exactly one profile-2
    Registry and no profile-1 dual-write, fallback, or merge path.

## Stop and pivot conditions

Implementation stops or narrows its claim if it requires any of the following:

- calling two effects a composite because they share a root or Registry;
- changing root constants without creating one operation-level `EffectId`;
- adapter-owned component terminality or a physical side ledger that can
  release resources without a core transition;
- whole-effect release as a prerequisite for every resource reuse;
- promoting an opaque `ResourceId` or QEMU guest coordinate into a physical
  ownership claim without hardware overlap and provider-custody evidence;
- reconstruction of a physical owner from raw PFN/IOVA numbers alone;
- pairing schema-5 estates by constants, order, time, or workload knowledge;
- starting schema 6 empty while live schema-5 state is ignored;
- accepting QEMU guest coordinates as physical-host evidence;
- allowing old and new Registries to coexist as live authorities; or
- weakening quarantine because a physical-hardware gate is unavailable.

## Non-goals

This RFC does not claim:

- novelty or firstness for causal identity, RPC recovery, durable outboxes,
  rollback admissibility, driver restart, reset, or IOMMU invalidation alone;
- universally exactly-once execution of an external effect;
- arbitrary dynamic workflow graphs or adapter-defined lifecycle callbacks;
- automatic semantic pairing of legacy durable objects;
- automatic schema-5 drain, import, or Registry rollover;
- a frozen canonical normalized differential-trace codec in this release;
- reconstruction of arbitrary pages allocated by an unmodified general
  allocator after a crash;
- cross-host ownership, lease consensus, or global freshness inside Nexus;
- hardware-general DMA quiescence from QEMU or one physical machine; or
- permission to revise historical evidence after implementation changes.

## Acceptance summary

The semantic/software and bounded QEMU requirements below have passed on the
current dirty worktree. RFC 0007 is release-sealed only when one clean,
source-bound evidence chain establishes:

- one real operation and one `EffectId` containing reply and DMA components;
- common effect authority and fencing with component-local lifecycle axes;
- typed component claims, partial discharge, and resource-local reuse permits;
- both revoke/effect-adopt winners in the production transition source, plus a
  second crash at every reachable partial state in the independent oracle and
  model-side Loom;
- profile 2, catalog v5, projection v6, recovery snapshot v2, and schema 6;
- candidate-selected schema-5 fail-closed rejection before current-catalog
  binding, plus independent proof that no pairing is inferred and no automatic
  migration exists;
- a single profile-2 production Registry after one cutover and no dual-write;
- dedicated-arena reconstruction before allocator/device activation;
- exact guest PFN/emulated-IOVA generation-plus-one reuse under the QEMU
  process-restart protocol claim;
- separate physical-hardware evidence before any physical PFN/IOVA reuse
  claim; and
- immutable RFC 0006 evidence and exact new receipts, negative results, and
  non-claims.

The detailed gate ledger is
[the composite-effect acceptance matrix](../research/cser-composite-effect-acceptance-matrix.md).

The final clean-source closure must be run after all intended changes are
committed:

```console
cargo test -p cser-model --all-features
cargo test -p cser-core --all-features
bash kernel/nexus-ostd/scripts/assert-cser-core-production-cutover.sh
kernel/nexus-ostd/x seal-core-persistent-recovery
```

The clean run writes `combined-receipt.txt` and
`combined-receipt.sha256` in the ignored production artifact directory. The
receipt must self-report the exact candidate `git_revision`,
`git_source_tree_clean=true`, `seal_requested=true`, and the bounded QEMU
non-claims. Its companion checksum, rather than a value copied back into this
tracked RFC, binds the receipt bytes. Embedding either the final commit SHA or
that receipt's digest in the same candidate commit would create an impossible
self-reference and would dirty the source after the seal.

Until such a receipt exists for the exact candidate revision, C0-C3 are
accepted as current dirty-tree evidence, no release label is authorized, and
C4/H-01..H-06 remain open.
