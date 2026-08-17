Maintenance constraint: the user decides when this file is updated. Unless the
user explicitly requests an update to `maproom/terrain.md`, treat it as
read-only rather than changing it merely because work progressed.

# Nexus terrain

## The problem

Nexus studies **Causally Scoped Effect Revocation (CSER)**: how work that has
escaped a restartable executor remains represented, fenced, and under custody
after that executor exits or is replaced.

Process death can revoke future authority. It cannot prove that an already
published reply, provider operation, queue entry, pinned page, DMA mapping, or
other external effect disappeared. Recovery must therefore keep several
lifetimes distinct:

- the executor, which may be fenced and replaced;
- the provider generation, which may stop ordinary execution while retaining
  settlement responsibility;
- the effect, which remains live until its outcome is established or
  reconciled;
- each logical or physical resource claim, which remains under exact custody
  until evidence appropriate to that claim authorizes retirement; and
- the recovery artifacts needed to interpret and settle the effect, which
  remain retained until every dependent obligation is retired.

CSER is a candidate compositional mechanism, not an exactly-once, rollback, or
production-readiness claim. If a provider, workflow database, attachment gate,
or workload-specific coordinator already supplies the same conjunction of
fencing, durable outcome recovery, exact custody, and evidence-bound release,
that is evidence against adding CSER to that workload.

## Safety model

The design rests on five durable requirements:

1. **Topology is bounded before escape.** An effect's admitted components and
   claims are catalog-defined before external publication. The bounded
   single-hop handoff is an explicit catalog rule, not a general workflow DAG.
2. **Authority is fenced effect-wide.** Executor or provider replacement
   advances durable recovery coordinates. A stale generation cannot create a
   new commit or silently inherit pending work.
3. **Custody is continuous and coordinate-exact.** A live claim is identified
   by resource identity and generation. An exclusive claim cannot have two
   executable custodians. A handoff transfers the exact source coordinate only
   at its durable custody pivot.
4. **Retirement is evidence-specific.** Logical outcome evidence and physical
   quiescence evidence are independent. Missing outcome evidence requires
   reconciliation; missing physical quiescence evidence retains the claim and
   refuses reuse.
5. **Recovery capability outlives the implementation that escaped.** Required
   provider code, schemas, catalogs, and verifiers are pinned before external
   commit and cannot be released until the dependent effects and claims are
   durably retired.

Pre-escape work may abort without pretending that an external event occurred.
Post-escape work must complete, reconcile, drain, reset, or remain retained.
Infrastructure failure, polling exhaustion, telemetry loss, and missing
observations never manufacture terminal business evidence.

## Authoritative core

`cser-core` is the portable authoritative state machine for escaped effects.
It owns effect admission, estates and bounded composites, claims, custody,
effect fencing, commit and settlement authority, retirement evidence, recovery
projections, journal records, checkpoints, and the invariants connecting them.

The core is not a plugin loader, dependency injector, semantic resolver,
workflow engine, artifact store, network trust stack, or hardware verifier.
Those systems allocate identities, select providers, execute code, retain
artifacts, and produce evidence. CSER binds their exact coordinates and
receipts, refuses unsafe transitions, and remains the canonical authority for
escaped-effect state.

Whole-state recovery must validate the catalog and canonical projection,
rebuild derived indexes, fence stale authority, retain unretired claims, and
restore settlement work without recreating opaque verifier authority from
projection bytes. The independent model crate owns only normalized oracles for
differential checks; historical specifications and release artifacts are not
parallel semantic owners.

## Scope and identity

The next core profile is provider-generation-aware. Its admitted effect scope
must distinguish at least:

```text
WorldId
ProviderId
ProviderGeneration
OperationId
EffectId
ChargeAccountId
```

The embedding allocates worlds, providers, generations, and operations. CSER
treats them as opaque exact coordinates and verifies their relationships.
`OperationId` is a general causal action identity: an agent runtime may bind an
`AgentActionId` to it, while a kernel or workflow may use another source
identity. Existing root, principal-incarnation, binding-generation, effect,
and charge identities must be reconciled with this model rather than retained
as unexplained parallel coordinates.

## Provider retirement crosses authorities

Provider retirement is a protocol among distinct authorities, not one broad
`Fenced` bit:

```text
semantic composition authority
  AdmissionFence and binding publication

runtime authority
  ExecutionFence

CSER authority
  EffectFence, SettlementOnly, outcome and claim retirement

artifact authority
  recovery-root pin and artifact retirement
```

CSER owns the effect-side gate: once a provider generation is effect-fenced it
cannot admit another escaped effect, while already committed effects remain
under exact custody. A generation may retain only settlement authority until
its obligations retire. CSER may bind receipts from the composition, runtime,
and artifact authorities, but no coordination record may independently advance
facts owned by those authorities.

## Catalogs and bounded composition

A sealed, digest-bound domain catalog defines the effect products that may
escape. Logical catalogs may describe remote operations, idempotency slots,
reply delivery, queued work, recovery custody, retained provider generations,
and artifact closures. Physical catalogs may describe pinned memory, IOVA,
queue entries, device generations, and evidence required for safe reuse.

The resolver may dynamically produce a new locked provider graph and a new
catalog generation. Effects already admitted under an older digest continue to
be interpreted and settled under that digest. A live catalog is never mutated
to change the meaning of an existing effect.

General workflow graphs remain outside the core. A workflow may admit new
effects over time, but each escape crosses a bounded admission gate. The
single-hop handoff remains a deliberately narrow custody-transfer primitive,
not an implicit recursive component API.

## Effect-driven recovery roots

An effect profile may require a durable artifact pin before external commit:

```text
durable artifact pin
-> effect commit intent
-> external dispatch
-> logical settlement
-> physical retirement
-> durable release authorization
-> artifact unpin
```

The artifact authority performs storage and garbage collection. CSER binds the
pin receipt to the exact world, provider generation, catalog, schema, verifier,
and operation that may need it. CSER issues release authority only after every
dependent effect and claim is durably retired. Retaining artifacts too long is
a reclaimable leak; releasing them while an obligation is live can make honest
recovery impossible.

## Transition and performance model

Durability remains part of the authority protocol. A transition may be
validated and prepared before persistence, but authoritative state cannot
change before its journal record and trusted anchor commit. Once persistence
succeeds, applying the prepared transition must be infallible; otherwise the
journal and in-memory authority can diverge.

The next core profile should make ordinary transition cost depend primarily on
the effects, claims, resources, and indexes touched by that transition rather
than on unrelated live state. Whole-state cloning, full invariant scans, and
full projection hashing on every transition are candidates for replacement by
prepared deltas, transition-local invariant maintenance, and incremental
authenticated projections. Recovery and checkpoint validation must still
rebuild primary state, derived indexes, and the complete canonical projection.

Copy-on-write collections, arenas, batching, journal layout changes, and lock
decomposition are possible techniques rather than architectural commitments.
Measurements on logical effects, physical claims, provider-generation drain,
and recovery decide which techniques remain. A single authoritative commit
writer is acceptable if unrelated full-state work has been removed and
persistence dominates; concurrency is not an end in itself.

## Reference paths and evidence boundary

The trusted-local asynchronous endpoint demonstrates exact-identity outcome
recovery. Adapter and provider durability are separate; a nonterminal or
unavailable observation does not authorize redispatch, and only authenticated
exact absence may do so. Remote authentication, provider registries,
multi-tenancy policy, and an SDK remain outside its implemented trust boundary.

The bounded handoff demonstrates evidence-bound custody transfer through a
prepared child and an atomic source-release/child-intent pivot. Its independent
baseline and QEMU experiments are logical evidence only. They do not establish
physical DMA or IOMMU quiescence, arbitrary late-bound composition, or a
general advantage over provider-native coordination.

Evidence vocabulary remains literal: **specified** names a concrete
obligation, **checked** names a bounded checker that ran, **observed** names a
concrete execution and environment, **inferred** names a conclusion drawn from
observations, and **unknown/right-censored** is retained when a required source
is absent. Evidence is source-bound and cannot be rebased onto a later semantic
profile.

Nexus does not currently establish whole-system proof, production SMP or
availability properties, physical power-loss or TPM anti-rollback, general
DMA/IOMMU quiescence, remote trust, workload prevalence, or statistically
powered general performance. A provider or hardware verifier supplies the
domain fact; the core cannot manufacture it from software state.

## Open terrain

The next core profile must determine the minimal provider-generation and
operation identities, the exact receipts connecting separate retirement
authorities, the recovery-artifact claim vocabulary, and the transition delta
that can be applied infallibly after persistence. It must also determine which
invariants can be maintained locally while preserving complete recovery
validation.

The central applicability question remains where CSER adds value beyond
coordination a provider or workload already needs. Logical remote effects,
physical device claims, and provider-generation retirement provide distinct
bounded workloads for answering it. Broader workflow composition, remote trust
policy, plugin loading, and semantic resolution remain outside the core even
when they consume its authority.
