Maintenance constraint: the user decides when this file is updated. Unless the
user explicitly requests an update to `maproom/route.md`, treat it as read-only
rather than changing it merely because work progressed.

# Nexus route

Nexus will prioritize a CSER Core rebaseline before optional integration with
external consumers. The selected outcome is a provider-generation-aware,
artifact-retaining, domain-extensible portable effect authority whose ordinary
transition cost is driven by touched state rather than unrelated live state.

Breaking API and on-disk format changes are permitted during this pre-consumer
phase when they produce a clearer foundation or measured benefit. Old profiles
will be rejected rather than preserved through compatibility shims. Existing
evidence remains immutable and source-bound; the new profile earns new evidence
after its semantics and implementation stabilize.

## 1. Restore the toolchain baseline

Migrate the current source to the selected Rust toolchain without combining the
compiler migration with CSER semantic changes. Establish a buildable and
testable starting point for the rebaseline.

## 2. Rebaseline identity and authority

Reconcile the existing root, principal-incarnation, binding-generation,
effect, and charge coordinates with explicit world, provider generation, and
operation scope. Define the effect-side provider lifecycle, settlement-only
authority, effect-driven recovery-root protocol, and verifier bindings needed
for exact logical and physical effects.

Express remote operations, idempotency slots, reply delivery, queued work,
recovery custody, retained provider generations, and artifact closures through
sealed domain catalogs wherever the current engine can enforce their
invariants. Change the engine only when a required invariant cannot be
expressed at the catalog or adapter layer.

## 3. Rewrite transition costs around changed state

Replace whole-state work on ordinary transitions with a prepared transition
model whose durable record and exact delta are validated before persistence
and whose post-persistence apply is infallible. Move suitable invariants and
projection updates to transition-local maintenance while retaining complete
rebuild and validation during recovery and checkpoint admission.

Use measurements across large logical-effect, physical-claim, and
provider-retirement workloads to select index, allocation, projection,
journal, batching, and concurrency changes. Do not treat copy-on-write,
mutex splitting, or the existing experimental vNext journal as predetermined
solutions.

## 4. Reestablish persistence and recovery

Define one coherent next-profile command grammar, journal, trusted-anchor,
checkpoint, projection, and recovery protocol. Cover provider-generation
fencing, settlement-only recovery, artifact retention and release, exact
replay, incomplete tails, rollback, and fail-closed persistence errors before
making the new profile authoritative in an embedding.

## 5. Migrate embeddings and renew evidence

Migrate the OSTD production owner, reply/DMA paths, asynchronous endpoint, and
bounded handoff to the new profile. Evaluate logical remote effects, physical
claims, provider-generation retirement, large-state transitions, persistence,
and recovery with bounded workloads and the strongest credible independent
baselines.

DeepSeek Harness or another agent runtime may later consume the resulting
effect authority through an external capability adapter. Plugin loading,
dependency injection, semantic resolution, general workflow DAGs, remote trust
transport, artifact storage, and hardware evidence production remain owned by
their respective systems rather than absorbed into CSER Core.

The sibling HotOS paper remains outside this route. Remote configuration,
synchronization, publication, and submission require separate explicit user
authorization.
