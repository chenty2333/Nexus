# CSER v6 Aggressive Semantic Cleanup

## Working stance

Nexus and CSER are still in a single-team research and development phase with
no external users. Breaking API, catalog, journal-adjacent, documentation, and
artifact changes are acceptable whenever they produce a concrete semantic or
research benefit. Do not preserve compatibility, append-only RFC history, or
old evidence merely as ceremony; Git history is sufficient for recovering old
states.

This freedom does not make semantic distinctions or experimental binding
optional. The current code, paper, and QEMU trace must still describe the same
contract, and every reported result must identify what was actually executed.

Do not implement a per-class unknown-evidence disposition algebra now. The
current safe rules are already axis-specific:

- unknown logical outcome enters reconciliation / remains indeterminate;
- unknown physical quiescence retains the claim and refuses reuse;
- administrative risk acceptance is not retirement evidence and is outside the
  normal safe-release path.

The absence of a second well-understood safe disposition is a design reason not
to add an algebra, not a compatibility or workload concern.

## 1. Make the conflict and conservation contract exact

Align the paper, code documentation, and current design notes around one exact
coordinate: conflict is evaluated among live claims naming the same opaque
`(ResourceId, generation)` coordinate. Different identifiers that alias one
physical extent remain the provider or hardware gate's responsibility.

Update I3 so each claim is bound to one `(eid, cid)`, one exact resource
generation, and one current custodian. Preserve custody transfer semantics;
do not imply that the custodian can never change.

Document Shared charging as intentional double accounting: credit measures
each live custody obligation, not deduplicated physical occupancy.

## 2. Describe retirement and abort as related but distinct operations

Do not force all release paths into one narrative or implementation shape.

- Evidence-backed estate and component retirement remove their exact reverse
  index entry and make a resource `Retired` only after both estate and
  composite indexes are empty.
- Pre-escape composite abort uses the same last-custodian conservation check,
  but may remove an original generation-1 coordinate or roll a pending reuse
  reservation back to the prior retired generation.

Retain the shared conservation rule while stating the different terminal
effects explicitly. Refactor only if it improves the implementation itself,
not to make the prose look uniform.

## 3. Keep ReusePermit terminology simple and its authority precise

Do not introduce “affine handle” into the HotOS paper. In API/design
documentation, describe `ReusePermit` as a non-cloneable handle backed by a
durable one-shot reservation.

Make clear that authoritative one-shot reuse comes from the retained
`PendingReuse` state and exact matching of actor, authority epoch, claim,
generations, catalog and retirement digests, reuse contract, nonce, and
freshness. Rust move semantics prevent ordinary caller mistakes but are not the
sole source of authority.

## 4. Separate evidence classification from runtime outcome transitions

Keep Outcome and Quiescence orthogonal:

- outcome evidence cannot authorize physical reuse;
- quiescence evidence cannot settle a logical outcome;
- physical claims may retire while the logical outcome remains unresolved.

`EvidenceCapability` is a catalog validation and digest-bound classification.
Logical outcome state is advanced through the separate verified effect-fact and
settlement paths. Remove the unused and misleading public
`EvidenceCapability::settles_outcome()` method rather than preserving source
compatibility for hypothetical callers.

## 5. Make unknown evidence globally fail closed in v6

Replace the RFC 0006 claim that every class declares its own conservative
unknown-evidence disposition with the rule the engine actually enforces:
unsupported or unknown evidence retains the claim, preserves its charge, and
cannot authorize reuse.

Automatic retirement contracts require recoverable evidence. `Ephemeral` may
remain useful as endpoint classification, but it must not imply that an
unimplemented fallback can safely release a claim. If a catalog cannot provide
a recoverable automatic path, reject that contract or leave it explicitly
outside automatic CSER retirement.

Add one focused failure-atomicity regression for unsupported evidence. It must
show `UnexpectedEvidence` and no change to revision/head, projection, claim,
charge, or resource gate. Do not build a new test framework for this case.

Defer any programmable disposition or administrative override until concrete
endpoints require at least two distinct policies and the design specifies
authorization, audit, persistence, replay, and which safety guarantees an
override relinquishes.

## 6. Align fence evidence, evaluation language, and the current QEMU trace

Explain the I2 evidence hierarchy rather than attributing a universal drain
proof to the portable core:

- the core serializes fence transitions, advances epochs, and rejects stale
  principal actions;
- production ingress, portal, and supervisor code close admission, reap the
  exact task, and bind the durable fence snapshot;
- the bounded QEMU profile supplies reset, IRQ, and IOTLB observations;
- none of this proves a universal or physical DMA drain barrier.

Describe the experiment by layer: real guest driver and interrupt/protocol
paths execute against QEMU/TCG devices, an emulated IOMMU, and swtpm. Continue
to exclude physical DMA drain, host PFN identity, physical power-loss
durability, and physical anti-rollback.

Keep deterministic and operational cost metrics distinct. The current
artifact reports credit-unit-revisions (36 in the bounded trace); a future
specified deployment may additionally measure retained resource-seconds.
Neither metric should be presented as the other.

The currently retained four-process evidence is bound to catalog v5 and journal
schema 6. Once the semantic and paper edits above are stable, run the final v6
four-boot QEMU trace once and make that the current artifact. It may replace the
development-facing v5 artifact; Git history is sufficient preservation. Until
then, the paper must not silently describe the v5 trace as a v6 execution.

## Shared extension boundary

Keep Shared as an implemented extension point rather than a standard-profile
or production-demonstrated claim. Add at most one focused complete lifecycle
test:

`shared custody -> first discharge remains retained -> final discharge -> ReserveReuse -> Activate -> generation+1 enrollment`.

Do not construct an exhaustive Shared topology/replay matrix without a real
consumer. If Shared remains outside the standard profile, say so directly in
the design notes and paper-facing claims.

## After this cleanup

Freeze mechanism work by judgment, not ceremony. Return effort to the research
questions that can change whether CSER is useful:

- compare against strong independent-finalizer baselines under injected crash
  windows;
- classify real agent/tool and device endpoints by recoverable outcome and
  quiescence evidence;
- build the smallest agent-tool adapter that exercises the contract;
- measure how often effects retire through evidence versus retained
  backpressure or operational intervention.

## Approved next phase: reference adapter, stability, and measured performance

### Scope and development location

Continue development on the local `main` branch of
`/home/ava/Desktop/Nexus`. The completed catalog-v6, tool-plus-DMA, baseline,
and crash-matrix work is the starting point; it does not need to be copied from
another directory.

Raise the endpoint work only to a reusable reference-adapter standard in this
phase. Remote receipt MAC/signatures, key rotation, verifier epochs, mTLS, a
machine-readable multi-provider registry, a second external endpoint,
multi-tenancy, quotas, backups, long-running service operations, and SDK work
remain deliberately deferred.

### 1. Complete the trusted-local reference adapter

1. State the trusted local sidecar threat model explicitly, including which
   processes and local transport boundary are trusted and why an unauthenticated
   digest is not evidence across a remote trust boundary.
2. Version the endpoint contract and implement durable
   `Accepted`/`Pending`/`Succeeded`/`Failed` states. Define which states are
   observations, which are terminal outcome evidence, and which cannot retire
   any physical claim.
3. Bind each terminal record to its namespace, effect identity, operation and
   input digest, catalog digest, and schema version so evidence cannot be
   replayed into a different contract.
4. Replace the compiled experiment identity with a persistently allocated
   random identity that survives endpoint and guest recovery.
5. Cover commit-before-apply, commit-after-apply, lost reply, restart query,
   and duplicate submit behavior with focused crash/idempotency tests.
6. Define evidence retention, expiry, database schema migration, and the
   fail-closed result when an observation can no longer be recovered. Expired
   or unmigratable evidence must never authorize claim release.
7. Add endpoint and bridge readiness, structured stage-specific errors, and
   basic counters/timings needed by the experiment without turning the adapter
   into a general service platform.

### 2. Harden experiment orchestration

Do these in order:

1. Give the UART-to-HTTP bridge an explicit ready/health signal and supervise
   endpoint, bridge, UART sink, and QEMU exits. Failures must identify the
   endpoint-connect, bridge-ready, guest-boot, first-byte, frame-complete,
   recovery-receipt, or cleanup stage.
2. Protect shared base-media provisioning with a directory lock or immutable,
   content-digest-addressed snapshots. Parallel baseline and CSER runs must
   start from byte-identical media without racing during first creation.
3. Replace the COM2/COM3 giant busy-spin loops with bounded polling batches and
   scheduler yield/backoff while preserving fail-closed host deadlines. Record
   transmit, first-byte, full-frame, and endpoint-response timing.
4. After the focused paths are stable, run bounded long-duration soak, injected
   endpoint/bridge/journal/TPM failures, and SMP/concurrency tests. Do not build
   a new test framework merely to inflate coverage; each case must exercise a
   concrete failure or race.

### 3. Measure before changing the performance architecture

Treat the following as candidate bottlenecks, not established conclusions.
Instrument them first with default-off or sampled telemetry and use the same
workload, storage, TPM, endpoint, and DMA envelope for CSER and the baseline.

Record transition queue/lock wait, candidate-state clone, invariant checking,
projection digest, journal append/sync/readback, TPM anchor advance, live-state
size, journal fill, and end-to-end adapter/recovery time. Exercise growing live
state and journal fill rather than reporting a single small-state number.

#### Full-state transition work

Measure the cost of cloning the complete engine state, running the canonical
invariant checker, and recomputing the projection digest on each transition.
If this dominates, introduce copy-on-write or transaction-local state,
incremental indexes/digests, and affected-region invariant checks. Retain the
canonical full checker and full digest as a test/debug oracle; a stale cache or
index must never make an unsafe admission possible.

#### ATA journal growth

Measure bytes and sectors read/written, flushes, readback, and transition
latency across journal fill ratios. If the current alternating-bank full-log
rewrite is the dominant growth cost, replace it with an append-oriented
segment layout plus a small committed header and bounded checkpoint/compaction.
Preserve failure atomicity, readback validation, and the journal-before-anchor
ordering at every crash cutpoint.

#### Runtime mutex serialization

Measure queue time and time spent holding the runtime mutex separately from
journal and TPM latency. Shorten the critical section only where candidate
work can be revalidated against the committed revision. Do not make state or an
external effect visible before its durable journal and anchor ordering is
established. Consider group commit or concurrency only after the single-order
contract is preserved and measurement shows serialization is material.

### 4. Completion standard for this phase

The phase is complete when the reference adapter's documented state and
recovery contract matches its implementation; orchestration failures are
bounded and stage-identifiable; parallel media preparation and delayed UART
paths are reproducible; soak/fault/SMP runs preserve fail-closed behavior; and
each performance change has paired measurements demonstrating that it removes
a measured cost without weakening the existing crash and invariant results.
