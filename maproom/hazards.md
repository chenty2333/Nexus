# Nexus hazards

This file records verified Nexus-specific failure modes that are easy to
repeat. It is not a status report, roadmap, result ledger, or general style
guide.

## Executor death is not outcome or quiescence evidence

Fencing a dead executor prevents new authority but says nothing about an
already escaped provider operation, reply, pinned page, or DMA mapping.
Treating death, timeout, polling exhaustion, transport failure, or missing
telemetry as terminal evidence can release a live logical or physical claim.
Unknown logical outcomes require reconciliation; absent physical quiescence
evidence requires exact claim retention.

## Endpoint retry authority is narrower than non-success

Only an authenticated full-identity exact 404 authorizes reposting the same
operation key. `Pending`, `Expired`, 410 tombstones, malformed replies,
unavailable transport, and mismatched identity or input are not absence. A
recovery path that collapses them into retry authority can duplicate an
external effect.

## Journal and anchor order is an authority boundary

The durable journal publication must precede trusted-anchor advancement. After
any disk mutation error, the active persistence instance is poisoned; its cache
cannot decide the committed endpoint. Advancing the anchor first, trusting an
uncommitted tail, or continuing from a stale cache can make recovery accept
state that was never durably published.

## A persisted prepared transition must be infallible to apply

A transition redesign may validate against immutable state and persist an
exact delta before updating the in-memory authority. Once that record is
durable, applying the prepared delta cannot perform another fallible business
check, allocate an unreserved resource, or hide a whole-state candidate clone.
A post-persistence apply failure would leave the journal ahead of the active
authority and make the running instance unable to represent its committed
state.

## A compatibility path is a second semantic owner

Legacy constructors, command variants, portal policies, fixtures, and replay
modes can keep an obsolete authority model executable even when production
uses a newer profile. Reusing one of those paths in a new adapter or evidence
run silently restores two meanings for admission, identity, or recovery. A
predecessor format may be recognized to reject it fail-closed; it must not keep
an active compatibility engine alive.

## A renamed global generation is still parallel authority

Wrapping a former raw binding generation in a newtype does not remove its
semantics. If a global authority-binding generation remains in state, journal
records, checkpoints, or trusted anchors, it can reject replay independently
of the exact world, provider, operation, effect, and executor coordinates. A
typed hard cut must remove that scalar from the wire and replay gate, not only
rename it. Static cutover checks should reject its reintroduction.

## Retirement fences belong to distinct authorities

Admission, escaped-effect creation, ordinary execution, physical reuse, and
artifact collection are controlled by different authorities. Collapsing
`AdmissionFence`, `EffectFence`, `ExecutionFence`, physical retirement, and
artifact retirement into one provider flag can either preserve stale authority
or release live obligations. Coordination may bind receipts from each owner;
it cannot manufacture one owner's fact from another owner's transition.

## Recovery artifacts must bracket external escape

Provider code, catalogs, schemas, and verifiers required for recovery must be
durably pinned before the effect crosses its external commit point. Their
release must follow durable retirement of every dependent effect and claim.
Pinning after dispatch creates a crash window with no recovery capability;
unpinning after logical outcome but before physical retirement can strand a
live claim.

## Live accounting and immutable verification provenance are different state

Releasing an effect may remove its live provider binding and decrement the
provider's drain counter, but persisted facts and evidence still require the
exact world, operation, provider generation, catalog, schema, and verifier
generation that authenticated them. Deleting that provenance makes a locally
accepted release unrecoverable; retaining it as a live binding prevents honest
provider retirement. Terminal transitions must release live accounting while
preserving immutable provenance, and full recovery invariants must validate
both sides independently.

An unpinned artifact placeholder is not historical artifact provenance. A
pre-escape abort may retract it, while a real pinned lease must reach exact
release confirmation before a normal release or handoff pivot can discard its
live scope.

## Incremental state must remain fully reconstructable

Transition-local indexes, invariants, and projection digests may remove
whole-state work from the hot path, but they cannot become unverifiable caches.
Recovery and checkpoint admission must rebuild derived indexes and the complete
canonical projection from primary state and reject any mismatch. Accepting an
incremental root without that reconstruction can preserve silent drift across
reboot.

An idempotent primary-state write may still be a semantic projection touch.
Cold recovery deliberately keeps the trusted anchor projection while adding a
fail-closed quarantine overlay; the following checkpoint can write the same
device generation and quarantine values already present in primary state while
needing to update the authenticated leaf. Filtering touches only by before/after
primary equality leaves a stale projection. Mutation helpers must record exact
write coordinates, and the full rebuild oracle must remain enabled in the
diagnostic profile.

## Durability publication cannot acquire new ownership

Every allocation and potentially fallible ownership conversion must finish
before journal append and trusted-anchor advance. In particular, caching an
owned whole-state checkpoint by cloning its journal record after the anchor
has advanced can fail or abort with durable state ahead of the in-memory
publication. Prepare the owned checkpoint replacement before entering the
durability boundary; the post-anchor suffix may only move prepared values and
clear latches.

## Handoff custody is exact and recovery data is not authority

The handoff conserves the exact `(ResourceId, generation)` coordinate. A child
is only a non-executable reservation until the atomic source-release/child-
intent pivot. Recovery projections expose descriptor and digest data for
revalidation but do not recreate verifier authority. Installing, observing, or
releasing from projection bytes alone bypasses the evidence-bound handoff
guard.

## Development backends do not establish hardware facts

QEMU/TCG is not physical-device evidence. MemoryDisk counters measure requested
provider operations, not ATA completion, physical flush durability, or
wall-clock latency. Promoting those observations into physical quiescence,
power-loss, TPM anti-rollback, or hardware-general performance claims crosses
the evidence boundary.

## Evidence cannot be rebased onto newer source

Committed evidence is source-bound. Editing an immutable bundle to describe
newer code, or citing an older bundle as a rerun of a later semantic
refinement, breaks that binding. Capture a new bundle when execution evidence
is needed; otherwise state the version boundary and preserve unknown or
right-censored fields.

Public bundles must not contain raw identities, operation keys, databases,
logs, media, TPM state, absolute paths, container identifiers, or HMAC keys.
In raw-authoritative mode, any abort or failed publication must leave a
machine-detectable incomplete marker rather than a readable complete set.

## Historical gates are not current semantic owners

The retired TLA vertical slices, trace replay, frozen-wire crate, research
ledgers, and broad xtask gates describe earlier project states. Reintroducing
them merely to preserve an old receipt shape creates a second source of truth
and can force current code to satisfy obsolete semantics. Historical recovery
belongs to Git history and immutable release artifacts.

## The sibling paper is outside this repository's authority

Do not configure, synchronize, push, publish, or submit the sibling
`nexus-hotos` repository or paper without explicit user authorization. Local
Nexus cleanup or evidence work does not grant that authority.
