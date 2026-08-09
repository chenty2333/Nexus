# CSER Research and Evaluation Plan

## Working stance

The catalog-v6 cleanup, reference-adapter, stability, measured-performance,
and late-bound Gate-0 phases recorded below are complete. They remain here as
the approved design record. Kubernetes DRA and NVMe Namespace Management did
not establish the required custody gap, so the synthetic G0/G1 pilot was not
promoted. The active phase is the evidence-driven asynchronous applicability
and safe-scaling plan at the end of this file.

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

## Approved next phase: late-bound custody falsification pilot

### Decision and scope

Treat late-bound custody as the leading mechanism-falsification experiment,
not as a preapproved dynamic-workflow product or a promise to expand the core.
The fixed tool-plus-DMA topology has already produced honest parity between
CSER and a strong independent finalizer. Repeating that topology with more
crash points will not establish a CSER advantage.

The pilot must be capable of weakening or falsifying the CSER necessity claim.
A workload-specific baseline may use correct fsync, durable outbox/inbox
records, idempotent recovery, provider generation fencing, shared persistence,
or a purpose-built coordinator. A shared table alone is not grounds for
renaming the baseline CSER. Semantic convergence may be claimed only if the
baseline actually needs durable late enrollment, a common fence and allocator
gate, and evidence-gated independent release.

This phase ends with a recorded Go/No-Go decision. A Go authorizes a separately
reviewed QEMU experiment plan; it does not automatically authorize a general
dynamic-component API, a parent/child workflow engine, or full productization.

### 0. Restore factual alignment

Before reporting new results, update the endpoint capability census so it no
longer describes the current CSER2 adapter as an `applied/success`-only
prototype. Keep the trusted-local threat boundary and the distinction between
outcome and quiescence evidence explicit.

Keep publication boundaries honest: the Nexus source is on GitHub, while the
generated comparison receipts remain Git-ignored, the small source-bound
evidence bundle is not yet published, and the sibling `nexus-hotos` checkout
still needs an explicit remote before its paper commit can be published.

### Gate 0: establish a credible late-bound workload

Write one concrete workload card before implementation. It must establish all
of the following:

1. Service A has durably accepted or produced an externally irreversible fact
   before the exact service-B identity or resource coordinate becomes known.
2. A and B belong to distinct persistence, recovery, or atomicity domains.
3. Executor replacement can race B admission and successor resource reuse.
4. The exact resource cannot be cheaply predeclared; wildcard reservation is
   either impossible or has a measurable availability or retention cost.
5. B has a real first-observation gate: no B call or DMA publication may occur
   before its authority and exact claim have been durably admitted.

A plausible candidate is an asynchronous planner that durably accepts a job
and only then selects an accelerator worker, queue, or DMA arena. This is a
candidate, not an assumed fact. The card must explain why the selection is
genuinely late-bound rather than a host parameter deliberately hidden from the
baseline.

If no credible workload satisfies these conditions, record No-Go and pivot to
endpoint-applicability and missing-evidence retention measurements. Do not
invent a dynamic graph solely to make CSER appear necessary.

### Gate 1: portable pilot with the existing core contract

Do not begin by adding components to an already prepared composite. The current
catalog fixes a composite's component product at creation and freezes claim
enrollment at preparation. First test the strongest handoff expressible by the
existing contract:

`A retained -> durably create B under the same root -> enroll B's exact claim -> release A -> permit B to escape`.

Use two graph shapes:

- **G0 static control:** A, B, and DMA are known before the first escape. A
  strong baseline should match CSER here.
- **G1 true late-bound handoff:** A's durable external result reveals B and its
  resource only after A may have escaped; B is admitted before its own first
  external observation.

Model the durable route or child descriptor as external evidence, never as an
unbound harness flag. In the portable pilot it may be a small modeled receipt;
a QEMU continuation must later carry it through the real endpoint contract.

#### Baseline ladder and fairness

Allow increasingly strong alternatives rather than choosing a strawman:

1. **Independent finalizers:** durable A outbox and B inbox, idempotent handoff,
   per-service epochs, correct local recovery, and no deliberately omitted
   persistence step.
2. **Provider-native generation fence:** B presents the exact resource
   generation at its real publication gate, which may reject stale work. This
   is the most important non-CSER counterexample.
3. **Wildcard reservation:** reserve every possible B resource before A
   escapes; evaluate at least 2, 8, and 32 candidates to expose or refute the
   claimed precision cost.
4. **Workload-specific coordinator:** if simpler baselines fail, allow a
   durable shared coordinator as an upper bound. Record exactly which common
   enrollment, fence, gate, and evidence-release semantics it needs.

All arms receive the same route fact, endpoint and device evidence, resource
generations, schedules, and recovery opportunities. Code size and number of
tables may be descriptive engineering evidence, but they are not a safety
proof or the primary result.

#### Required schedules

Enumerate four critical windows, followed by one second crash during recovery
for each:

1. B reads the old epoch, then the root is fenced before B's inbox and claim
   become durable.
2. B's claim becomes durable, then the system crashes before A records the
   handoff acknowledgement or releases its retained state.
3. A releases its handoff state, then the system crashes before B's first
   external publication.
4. B publishes DMA, then the system crashes before quiescence evidence and
   claim discharge while a successor attempts conflicting reuse.

Keep the static G0 control small. Do not turn the pilot into a Cartesian QEMU
matrix before these schedules establish a semantic difference.

#### Hard properties and cost observations

Every arm must report:

- zero external publication without durable enrollment;
- zero conflicting reuse while a live claim or provider fence forbids it;
- zero stale or mixed-generation admission;
- zero duplicate child adoption or external application;
- complete recovered custody with a stable second recovery;
- retained claims or wildcard reservations by resource and generation;
- gate allow/reject counts;
- reconciliation steps and, where a real clock exists, delay;
- permanent-retain or administrative-disposition outcomes under missing
  outcome or quiescence evidence.

### Pre-registered decision rules

Record No-Go for full QEMU expansion if any of the following occurs:

- CSER admits an unregistered publication, conflicting reuse, stale
  generation, or unstable second recovery.
- Independent journals plus an idempotent protocol, or a provider-native
  generation fence, pass every window without a common linearization gate and
  without material over-retention. This weakens the common-custody necessity
  claim and is a valid research result.
- CSER can pass only after adding a general dynamic-component operation,
  hidden adapter authority, or a new parent/child core primitive. Stop and
  review that semantic change separately rather than moving the experiment's
  goalposts.
- Wildcard reservation has no material retention or availability cost over 2,
  8, and 32 candidates.
- Missing evidence makes permanent retention or administrative disposition
  operationally dominant for the chosen workload.

Record Go only if CSER satisfies every hard property and the strongest simpler
baseline either exposes a reproducible custody gap, pays measurable wildcard
retention, or must introduce the common late-enrollment, fence, allocator-gate,
and typed evidence-release contract under examination.

The strongest defensible conclusion is workload-bounded: in this late-bound
handoff and fault matrix, a predeclared independent finalizer either loses
coverage, retains conservatively, or reconstructs the relevant custody
contract. Do not claim that state machines, transactions, or independent
finalizers cannot express the behavior in general.

### Gate 2: conditional real-QEMU continuation

Proceed only after Gate 0 and Gate 1 produce Go. The smallest continuation is:

1. Extend the trusted-local endpoint with a durable, evidence-bound route or
   child descriptor. It must survive lost replies and restart queries and must
   not be supplied through COM3 or another host-only shortcut.
2. Make effect identity row-scoped if the experiment requires distinct A and B
   effects; keep authority, namespace, catalog, retention policy, and schema
   sidecar-bound where appropriate.
3. Give A and B independent durable stores/finalizers and use the same external
   facts for every comparison arm.
4. Connect two or more actual resource coordinates to the authoritative guest
   allocator/device gate so old-live blocks the selected conflict while an
   unrelated route remains admissible.
5. Run G0 and G1 across the same semantic crash cuts for CSER and the selected
   strongest baselines. Add missing/expired endpoint evidence and delayed or
   absent DMA quiescence without constructing an exhaustive fault product.
6. Measure selected-resource retention, wildcard over-retention, gate
   rejection, evidence-to-retirement delay, reconciliation, journal/anchor
   work, permanent retain, and administrative disposition.

Only if adapter-level create-before-release cannot express the required
custody after this pilot should a durable parent-to-child edge be proposed.
Such a proposal must specify replay, conservation, reverse indexing,
retirement, fencing, and baseline-equivalent authority before implementation.

### Explicit deferrals

Do not pull these into the pilot without a new measured or semantic need:

- general dynamic workflow graphs or arbitrary component insertion;
- remote receipt signatures, mTLS, provider registries, multi-tenancy, SDKs,
  or a second cloud-product integration;
- copy-on-write core state, segmented journals, or runtime-mutex splitting;
- physical-hardware generalization or cross-CPU CSER transactions;
- a full QEMU matrix before the portable Go decision.

### Completion standard

This phase is complete when the workload card is credible or explicitly
rejected, the fair baseline powers and schedules are frozen, the G0/G1
portable pilot has reproducible safety and retention results, and one explicit
Go/No-Go record determines whether a real-QEMU continuation is justified.

## Approved next phase: evidence-driven asynchronous applicability and safe scaling

### Working stance

This remains an early single-team development project. Contracts, workload
cards, measurement thresholds, and fault cuts are working decisions rather
than permanent compatibility promises. Change them when implementation or
evidence shows a better boundary, and record the reason in the current design
or result. Do not preserve a weak experiment merely because it was once
written down.

Development flexibility does not relax the safety semantics that the
experiment is intended to exercise:

- a nonterminal or unavailable outcome is not retirement evidence;
- infrastructure failure is not a verified application failure;
- missing quiescence evidence retains the affected physical claim;
- telemetry loss cannot make an operation absent, terminal, or reusable; and
- durable state, journal publication, and anchor advancement remain ordered.

The phase has two primary deliverables: a genuinely asynchronous trusted-local
reference endpoint, and a source-labelled applicability trace pipeline. It
also implements a bounded single-hop child descriptor/handoff and uses the new
workload to drive a real performance optimization cycle. It does not build a
general workflow engine, remote trust platform, or arbitrary dynamic-component
core.

### 1. Implement the applicability trace contract

Create a versioned event contract whose unit is one sampled effect, not one
HTTP request. Keep the collector outside the trusted core: failure, delay, or
event loss may reduce measurement quality but must never alter admission,
settlement, retirement, or reuse.

Each trace must be able to record:

- a study and endpoint-profile identity;
- study-local pseudonymous effect, operation, and resource identities;
- operation and resource classes without payload, prompt, result body, URL,
  token, tenant name, or raw resource identifiers;
- source labels for endpoint, worker/provider, guest, allocator gate, device,
  and operator observations;
- registered, submitted, accepted, pending, terminal, quiescent, retained,
  released, gate-rejected, administrative-disposition, and observation-ended
  events;
- declared and observed Outcome/Quiescence capabilities;
- whether an idempotency record, lease, scheduler, attachment gate, workflow
  database, or another provider-native coordinator already owns first
  observation;
- executor, endpoint, and resource-authority domains;
- relative monotonic timing, bounded wall-clock buckets where useful, source
  confidence, and reason codes; and
- dropped-source counts and right-censoring for incomplete observations.

Keep declaration, observation, system result, and research inference separate.
Missing events become unknown or right-censored, never absent. Use a per-study
HMAC salt for published identities and retain raw source-labelled traces
locally. Every aggregate must state the sampled denominator; a reference-
adapter run validates the pipeline but does not establish industry prevalence.

Implement a bounded recorder, schema validator, and aggregator. Produce a raw
JSONL or SQLite trace plus a summary containing denominator, terminal outcome,
quiescence, retained/released claims, gate decisions, administrative outcomes,
right-censored effects, and missing-source counts.

### 2. Turn the reference endpoint into a real asynchronous service

The current Store already models Accepted, Pending, Succeeded, Failed, and
Expired, but normal HTTP POST completes synchronously. Make the asynchronous
contract real rather than exposing a test-only transition.

Use two independently durable domains in the reference implementation:

- the adapter database stores operation identity, Accepted/Pending state,
  worker scheduling, and immutable terminal evidence; and
- a provider database stores the controlled external effect, exact-key
  deduplication, and queryable outcome.

POST must durably create Accepted state and a queue entry before returning
202. A worker transactionally acquires a lease, persists Pending, executes
outside the database lock, and commits Succeeded or Failed through a matching
lease token. Lease expiry permits recovery, but never supplies exactly-once by
itself: the provider must accept the complete operation identity as an
idempotency key or support exact outcome queries. Recovery must query before
redispatch when apply may have happened.

Failed means a verified application result. Timeout, transport failure,
worker death, retry exhaustion, and provider unavailability remain Pending or
unknown and preserve custody. Separate operational retry deadlines from
terminal-evidence retention. Accepted and Pending must not age into apparent
completion; terminal evidence starts its retention clock only when a terminal
record is durably created. Expired terminal evidence remains a fail-closed
tombstone.

Version the changed HTTP/database contract rather than preserving accidental
v2 behavior. A migration may deliberately fail closed; there are no external
compatibility obligations.

Cover at least these focused recovery boundaries, adjusting exact cuts as the
implementation evolves:

- Accepted committed before a worker claims it;
- Pending committed before provider apply;
- provider apply committed before adapter terminal commit;
- terminal commit before the client receives a reply;
- competing worker leases;
- endpoint, worker, and provider restart; and
- duplicate POST in every observable state.

### 3. Teach the guest to reconcile nonterminal operations

Represent endpoint results explicitly as terminal, nonterminal, absent,
expired, or transport/protocol failure. Accepted and Pending keep the effect
and claims live. The guest may use bounded polling with yield/backoff, but
exhausting a polling budget only ends the current recovery attempt; it does not
create a business failure or retirement evidence.

Recovery first performs an exact identity query. Pending never authorizes a
new operation. Preserve the narrow exact-404 retry rule, the 410 tombstone, and
full identity/checksum/evidence verification for terminal records. Tool
outcome and DMA quiescence continue to retire independently.

Add a small number of focused host/QEMU scenarios for asynchronous completion,
Pending across a crash, provider apply before terminal commit, indefinite
Pending retention, and tool-before-DMA retirement. The cuts are development
regressions, not a frozen exhaustive matrix; reuse the existing matrix only
where it materially reduces duplicated setup.

### 4. Add a bounded child descriptor and single-hop handoff

First extend terminal output with a bounded, digest-bound result capable of
carrying `ChildDescriptorV1`. The descriptor binds parent and child identities,
route or discovery digest, child profile, exact resource generation, input
digest, catalog digest, and schema version. Derive a stable child identity from
the parent, sequence, and descriptor digest. Carry the descriptor through the
endpoint evidence path, never through COM3 or another unbound harness flag.

Implement one adapter/runtime-level handoff using existing ordinary child
effects under the same root:

`A retained -> descriptor durable -> create B -> enroll exact B claim ->
prepare B -> release A -> permit B first observation`.

Keep a safe overlap across crashes, make creation/adoption idempotent, and give
the comparison baseline the same descriptor. The runtime policy may enforce
the single-hop sequence without teaching the core a general causal graph.
Use a few focused cuts around discovery, child enrollment, parent release, and
child publication; adjust them when they cease to illuminate the code.

Do not add arbitrary component insertion, nested workflow graphs, recursive
retirement, or a general reverse child index in this phase. If the adapter
cannot make the handoff recoverable without a core guard, stop that slice and
specify the smallest required invariant separately before changing the core.

### 5. Build phase-resolved performance evidence

Use the asynchronous endpoint and recovery path as the primary workload.
Expose default-off measurements for candidate-state construction, clone,
canonical invariant checking, projection digest, journal append/sync/readback,
TPM anchor work, runtime mutex queue/hold time, endpoint queue/provider time,
live claims, journal fill, and recovery latency.

Run representative development sweeps over small and large live state,
journal fill, delayed endpoint completion, and available concurrency. The
exact sizes and repetitions are tunable; retain enough fixed points to compare
before and after results. Distinguish diagnostic cycle counts from calibrated
time.

### 6. Replace the accumulating double-bank journal with append/checkpoint

The measured double-bank layout has structural cumulative rewrite
amplification. Implement an append-oriented journal generation with:

- sequential hash-chained records;
- length, revision, previous-head, and checksum validation;
- redundant committed headers or superblocks;
- record flush and readback before committed-head publication;
- journal publication before trusted-anchor advancement;
- bounded checkpoint/compaction into an alternate segment; and
- recovery that selects the newest valid committed prefix and ignores an
  uncommitted tail.

Because this is a development tree, use a new schema and fail closed on old or
ambiguous media rather than carrying compatibility machinery without value.
Exercise representative torn record, torn header, interrupted checkpoint,
readback failure, corrupt reopen, fill, and second-recovery cases. The list is
adjustable, but the publication and replay invariants are not.

Re-run the same phase measurements and report sectors, bytes, flushes,
readback, fill behavior, transition latency, and recovery cost before and
after.

### 7. Optimize core state or runtime serialization only when observed

If clone, invariant, or digest work is material in the integrated workload,
introduce a transaction-local overlay, copy-on-write state, or incremental
indexes/digests. Retain the canonical full checker and full projection digest
as differential test/debug oracles. No cache or fast index may make a corrupt
or conflicting state admissible.

If multiple writers create material runtime queueing, consider preparing a
candidate outside the authoritative mutex and committing it only after exact
base-revision revalidation. Keep journal and anchor publication ordered; do
not expose uncommitted state or external effects. Do not split the mutex merely
because telemetry exists, especially while the production scheduler remains
BSP-oriented.

Measurement gates in this section are development judgments, not permanent
thresholds. Record why an optimization was taken or deferred and keep the
before/after workload comparable.

### 8. Applicability sample and completion standard

Use the collector on the new asynchronous adapter and on at least one bounded,
source-identified endpoint or local system workload. Good candidates include
agent code/sandbox workers, asynchronous batch or CI jobs, fire-and-forget
negative controls, and local accelerator/RDMA/VFIO/SPDK-style brokers. Treat
existing schedulers, provider leases, workflow databases, and attachment gates
as first-class results rather than excluding them.

The implementation phase is complete when:

- POST/Pending/worker/provider/recovery are genuinely asynchronous and
  preserve exact-key idempotency across the focused crash cases;
- guest reconciliation never converts nonterminal, expired, unavailable, or
  missing observations into terminal evidence;
- the trace pipeline emits source-labelled, drop-aware raw data and honest
  aggregates for a bounded sample;
- `ChildDescriptorV1` and the single-hop adapter handoff are evidence-bound,
  replayable, and do not require a general dynamic-component core;
- the append/checkpoint journal passes its publication/recovery checks and
  shows a before/after reduction in cumulative rewrite work; and
- integrated measurements either justify and validate a core/runtime
  optimization or record why it remains deferred.

Remote receipt authentication, mTLS, multi-tenancy, SDKs, a general provider
registry, physical-hardware generalization, and a general workflow graph remain
outside this phase unless a concrete implementation dependency appears.
