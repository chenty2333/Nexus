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
