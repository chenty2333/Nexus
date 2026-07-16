# RFC 0001: identity-preserving production-path CSER composition

- Status: **Draft / prospective research contract**
- Target: a possible Nexus `v0.2.0` evidence release
- Supersedes: nothing
- Changes accepted `v0.1.0` claims: **no**

## Claim discipline

This RFC defines a hypothesis and the evidence that would be required to test
it. It does not, by itself, report a completed implementation or accepted phase.
The bounded implementation checkpoint recorded below is narrower than the full
contract. In particular, the words **production path**, **shared**, **same
boot**, **identity preserving**, **SMP**, and **measured** below name prospective
acceptance requirements unless a checkpoint names the exact narrower
observation.

Here, **production path** means the normal Nexus/OSTD path that would execute the
operation without an evaluation-only state machine. It does not mean
production-ready, secure against every attacker, hardware-general, or suitable
for deployment.

The accepted `v0.1.0` result remains bounded by its own release manifest and
narrative. It uses fresh composition effects, bounded outer service-binding
envelopes, case-local Stage 7B fault ledgers, a single-vCPU evaluator, and a
separate-boot Stage 5B device receipt. No result from this RFC may be attributed
to `v0.1.0`, and old evidence may not be relabeled as evidence for this RFC.

### Bounded implementation checkpoint (2026-07-16)

One focused one-vCPU OSTD/QEMU vertical slice now observes the retained Linux
filesystem guest block outside all kernel locks while a distinct user-mode
`fsd-v1` task registers and prepares its filesystem effect in the shared
production Registry. Each portal derives the complete sender `TaskKey` from the
current OSTD `Task`; after Prepare, v1 queues a typed delayed `Prepare` containing
that v1 key and its old `PortalHandle`. A real user-mode page fault then
terminates v1 before device enrollment or commit.

Only after the v1 completion waiter returns and the protocol phase is confirmed
`Crashed` does the slice construct the v2 `VmSpace`, completion waiter/waker, and
OSTD `Task`. That fresh `fsd-v2` performs Snapshot, Ready, Rebind, and explicit
Adopt of the same effect. V2 then only triggers delivery of v1's already-queued
command: the saved v1 sender plus old handle returns `StaleBinding`, and the same
old sender plus the adopted handle returns `NoSupervisor`; both leave the full
Registry failure-atomic projection unchanged.

After recovery, the normal lane enrolls the exact six-effect workload/device
cohort, crosses the real `avail.idx` Release point, executes same-boot
VirtIO/IOMMU DMA, drains through reset and IOTLB recovery, and publishes one
guest result. A paired pre-commit lane lets revoke win before device publication
and publishes one `AbortedBeforeCommit` result. Both lanes use polling with PCI
INTx masked.

This checkpoint establishes only the named real filesystem-service crash point
before device commit. It does not observe the required crash after device commit
but before guest reply, every frozen fault cell, a real interrupt path, 2-vCPU or
4-vCPU behavior, all filesystem fault paths, a performance result, or full
production-adapter equivalence. It does not close Phase 2, Phase 3, this RFC, or
the prospective `v0.2.0` result.

## Summary

The proposed `v0.2.0` study asks whether the same kernel-owned causal identity
can survive a real mixed service path from a Linux filesystem read through
VirtIO queue publication and IOMMU ownership, across service crash/rebind and
root revocation, while all participating effects and resource credits remain in
one shared production registry and ledger.

The first workload is deliberately narrow: one block-backed filesystem read in
one boot. Its value is not filesystem breadth. Its value is that the request
must cross personality, filesystem, block, VirtIO, DMA/IOMMU, and guest-reply
boundaries without replacing the root, effect, ticket, binding, resource, or
device identities with an evaluation-only cohort.

The study additionally requires a documented refinement of abstract CSER
linearization points to real OSTD locks, interrupt exclusion, memory ordering,
and 2-vCPU and 4-vCPU execution. Loom or other bounded concurrency models remain
useful, but they are supplemental evidence rather than substitutes for the
actual lock and IRQ path.

## Hypothesis and research questions

The prospective hypothesis is:

> A kernel can preserve one causal authority and resource-accounting identity
> across a real block-backed filesystem read, restartable service recovery,
> same-boot VirtIO/IOMMU ownership, and root revocation, while maintaining
> post-revoke commit exclusion, single terminalization, typed-credit
> conservation, and honest timeout/tombstone behavior on 2-vCPU and 4-vCPU OSTD
> executions at a measurable cost.

The hypothesis is divided into five research questions:

1. **RQ1 — identity:** Can every effect and resource owner in the live workload
   retain one immutable causal ancestry from registration through publication,
   recovery, and closure?
2. **RQ2 — failure atomicity:** Can the production transition object, shared
   registry, typed ledger, reverse indexes, and domain resource state reject or
   recover from injected failures without partial mutation, copied credit, or a
   hidden side ledger?
3. **RQ3 — concurrency:** Do real OSTD lock, IRQ, and memory-ordering choices
   preserve the abstract winners under 2-vCPU and 4-vCPU execution?
4. **RQ4 — device closure:** Can one same-boot device session retain DMA owners
   through queue publication, reset or IOTLB timeout, late acknowledgement, and
   final release without substituting another effect or generation?
5. **RQ5 — cost:** What steady-state, recovery, closure, memory, and contention
   costs does this mechanism add relative to predeclared baselines?

A positive result is not assumed. `Checked`, `Observed`, `Measured`, and any
contribution decision may be used only after their corresponding gates below
have produced accepted evidence.

## Non-goals

This RFC does not propose to:

- establish novelty, firstness, a whole-system proof, lock freedom, or
  production liveness;
- implement a general VFS, page cache, permission model, namespaces, writable
  persistent filesystem, TCP/IP stack, or broad Linux compatibility;
- roll back a durable write, transmitted packet, or other effect already made
  externally visible;
- support arbitrary causal DAGs, nested authority scopes, or effects with
  multiple roots in this release;
- support arbitrary devices, transports, queues, clients, or physical PCIe
  platforms;
- design a new block protocol, filesystem format, TCP/IP stack, boot path, or
  IOMMU implementation when a maintained component can be wrapped at the CSER
  boundary;
- make a hard real-time, low-overhead, or cross-machine performance claim from
  TCG observations;
- require lock-free data structures or a maximally concurrent design. A small,
  documented per-root serialization scheme is admissible if it meets the safety
  and measurement gates.

Nested scopes and multiple-root effects remain separate research questions.
They must not be smuggled into `v0.2.0` through an undocumented parent field or
an evaluation-only graph.

## Identity vocabulary

Names in this section describe required semantic fields. They do not freeze a
Rust API or wire layout.

### Root authority identity

A root authority is named by:

```text
RootIdentity = {
    registry_instance,
    scope_id,
    scope_generation,
    authority_epoch,
}
```

`registry_instance`, `scope_id`, and `scope_generation` identify the authority
lineage. `authority_epoch` identifies the currently open or closing authority
generation. `RevokeBegin` advances the authority epoch but does not manufacture
a new root lineage for the effects already in the closing cohort.

Identifiers must not wrap or be silently reused. Exhaustion must be an explicit
error or be prevented by a justified allocation scheme.

### Service-binding identity

Each restartable domain has an independent binding identity:

```text
BindingIdentity = {
    root_lineage,
    domain_id,
    service_instance,
    binding_epoch,
}
```

A crash advances only the affected domain's binding epoch. Rebind attaches a
replacement to that already advanced epoch. Rebind alone transfers no effect;
each eligible uncommitted orphan requires explicit `Adopt`. Committed work
remains kernel-owned and is never recommitted by a replacement.

The production registry must own the binding table used for authorization. A
separate evaluation envelope may not be the only source of the seven domain
bindings.

### Effect identity and ancestry

An effect is named by an opaque, kernel-issued identity containing at least:

```text
EffectIdentity = {
    registry_instance,
    effect_id,
    effect_generation,
    root_lineage,
    originating_binding,
    domain_id,
    immutable_parent,
    operation_class,
}
```

`immutable_parent` is either the root or one earlier effect in the same root
lineage. The kernel installs the ancestry edge atomically with registration,
credit reservation, and reverse-index membership. User space may propose a
parent handle but may not mint or rewrite ancestry.

Adoption may update the current binding authorized to complete an eligible
effect. It must not change the effect ID, generation, root lineage, origin
binding, immutable parent, operation, commit identity, or retained resource
identity.

For this RFC the accepted ancestry is a finite, dynamically instantiated tree
within one root. The workload may contain forks and chains, but no effect may
have multiple parents or cross to another root.

### Commit, publication, and terminal identities

The first externally meaningful publication produces a non-forgeable commit
receipt bound to the complete effect identity, authority epoch, accepted binding
epoch, domain revision, and a registry-local sequence or nonce. A later
publication ticket and terminal receipt must be derivable from that commit
receipt without allowing the public fields to reconstruct authority.

Recreating the same visible integers in another registry instance, device
session, or process must not produce an acceptable receipt. Commit,
publication, reset, closure, and terminal receipts must be non-copyable or
otherwise enforce exactly-once consumption.

### Resource and device identity

Every resource charged to the workload has an opaque resource identity and a
typed credit class. The first workload must distinguish at least control,
filesystem operation, queue slot, pinned page, DMA mapping, and guest-reply
credits. An implementation may use finer classes but may not merge DMA
ownership into an unrelated scalar population count.

The same-boot device path additionally carries:

```text
DeviceIdentity = {
    pci_function,
    transport_instance,
    queue_id,
    device_generation,
    iommu_domain,
    dma_owner_ids,
}
```

Reset may advance `device_generation` only after the selected reset
acknowledgement. IOMMU completion controls when each retained DMA owner may be
released. Neither event may replace the CSER effect identity or root lineage.

### Closure identity

`RevokeBegin` returns an opaque revoke ticket bound to the root lineage, closing
authority epoch, frozen live-effect cohort, frozen typed-credit obligation, and
closure revision. Domain closure receipts must name that ticket and the current
domain, binding/device generation, and receipt revision. A stale, replayed,
out-of-order, cross-root, or cross-registry receipt must reject without semantic
mutation.

## No-synthetic-cohort rule

The evidence-bearing root cohort must consist of effects created by the normal
workload path. The following are forbidden as positive acceptance evidence:

- registering a fresh set of effects in an evaluator solely to resemble the
  workload after the real workload has already completed;
- treating an earlier revoked filesystem or network scope as a member of a new
  root merely because both ran in the same boot;
- joining a separate-boot device receipt to the primary workload and calling
  the result identity preserving;
- translating one effect, ticket, binding, or device generation into an
  unrelated fixed number in another state machine;
- using case-local credit ledgers as a substitute for the root's production
  ledger;
- generating a positive trace marker without executing the normal portal,
  registry, queue, completion, and closure transitions it claims to observe.

Instrumentation and fault injection are allowed. Evaluation code may choose
when a normal operation pauses, crashes, resumes, or fails, but it may not create
an alternate success transition. Each accepted effect must be discoverable in
the production registry from its first registration until terminalization or an
honestly retained tombstone.

The verifier must include negative mutations that deliberately substitute a
fresh cohort, another registry instance, another device session, or another
generation and demonstrate rejection.

## Shared production registry and ledger

All effects in the accepted workload must belong to one root in one production
registry instance. That registry must own:

- the root state, authority epoch, and commit/revoke gate;
- the per-domain service-binding table;
- immutable effect ancestry and operation identity;
- effect lifecycle, commit, publication, terminal, and adoption records;
- typed capacity, free, held, committed, returned, and retained credit
  dispositions;
- scope, parent/child, task, domain, and resource reverse indexes required by
  closure;
- the frozen revoke cohort and closure receipt allocator;
- tombstone ownership and the generation/revision needed to retry it.

Domain payload state may remain in typed scheduler, pager, filesystem,
readiness, or device objects. When one logical transition changes both domain
state and registry state, the implementation must document how it remains
failure atomic. Admissible designs include a common per-root lock, an infallible
validate/apply critical section with preallocated storage, or an immutable
receipt protocol whose incomplete side is safely retryable. The RFC does not
preselect one design.

The following are not admissible:

- a detached credit sidecar whose outcome is copied into the evidence later;
- separate case-local registries for each fault cell in the acceptance matrix;
- a mutation that can allocate or panic after one object becomes visible but
  before its corresponding registry/credit state is committed;
- reconstruction of a lost registry transition from a user-controlled trace;
- a global history scan hidden behind an uninstrumented helper.

Every fallible transition must either leave the complete semantic projection
unchanged or leave a valid, discoverable committed obligation. Allocation
failure, validation failure, stale tokens, wrong identities, and replay are
ordinary error outcomes, not permitted kernel panics.

## First workload: a block-backed filesystem read

The first accepted workload is one reproducibly built static Linux guest that
opens and reads a known file through the Nexus Linux personality. The file's
payload must come from an actual same-boot VirtIO block request, not an in-memory
success substitute.

The minimum causal path is:

```text
Root
`-- FilesystemSyscall                 Personality / Control
    `-- FilesystemRead                Filesystem / Filesystem
        `-- BlockRequest              VirtIO / Queue
            |-- DmaQueueOwnerA        VirtIO / DMA
            |-- DmaQueueOwnerB        VirtIO / DMA
            `-- DmaRequestOwner       VirtIO / DMA
```

If page-fault or scheduler effects occur in the normal execution, they must join
the same root with their real ancestry; they may not be logged as unrelated
prerequisites. The exact graph, credit classes, and publication points must be
frozen in a successor specification before implementation acceptance.

The read must exercise these distinct boundaries:

1. personality captures an immutable syscall request and registers the root
   effect;
2. filesystem policy resolves a fixed inode/block mapping and registers the
   filesystem child;
3. the block portal reserves queue and DMA resources in the shared ledger;
4. descriptor contents and DMA mappings become ready without device
   publication;
5. `avail.idx` Release is the conservative device `Commit` point;
6. the same queue/session is notified and completed in the same boot;
7. completion validates the full effect, device, queue, descriptor, and
   generation identities exactly once;
8. data publication to kernel-owned or guest-visible memory is explicitly
   ordered and recorded;
9. guest reply is a separate one-shot publication after the backend result;
10. root closure returns every releasable credit or retains an honest
    tombstone.

The expected file bytes, block image, guest ELF, and relevant build inputs must
be digest bound. The oracle must prove that the returned bytes came through the
device-backed path. A read is chosen first so that this RFC can study identity
and quiescence without pretending to solve durable-write rollback.

At minimum, the workload must admit a filesystem-service crash before device
commit, a crash after device commit but before guest reply, replacement
ready/rebind/explicit adoption where legal, stale old-binding rejection, and a
root revoke racing the device publication boundary.

The bounded checkpoint above observes the first crash point and the associated
replacement/stale-binding behavior in both normal and revoke-wins lanes. The
post-device-commit/pre-reply crash and the rest of the frozen fault population
remain required; adjacent normal-completion evidence cannot substitute for
them.

## Same-boot VirtIO/IOMMU obligations

The primary Nexus/OSTD boot must create the root, execute the guest read, submit
the real VirtIO request, observe the selected completion path, perform any reset
and IOMMU invalidation needed by injected cases, and close or honestly retain the
same root. A separate Stage 5B boot may remain regression evidence, but it cannot
satisfy this gate.

OSTD remains the single owner of the VT-d control plane. Nexus owns CSER
validation, deadline, reset/tombstone policy, and the decision to release an
owner only after consuming an OSTD-issued invalidation completion. No second
component may program the same domain or invalidation queue independently.

The same-boot evidence must show:

- one real `ACCESS_PLATFORM` VirtIO block request;
- non-identity DMA mappings whose owners are registered in the shared ledger;
- descriptor initialization before `avail.idx` Release and notification after
  publication;
- at least one normal completion through the selected real interrupt path, with
  interrupt acknowledgement and completion validation ordered explicitly;
- a reset timeout that retains the device session, queue, mappings, frames, and
  typed credits rather than reporting `Revoked`;
- retry using the same effect and root identity with a newly authorized device
  generation;
- queued IOMMU invalidation completion before backing-frame release;
- rejection of a late or duplicate completion from the old binding, queue, or
  device generation without a second publication or terminalization.

If the pinned platform cannot provide the selected interrupt or IOMMU behavior,
the result must be reported as blocked or negative. Polling-only or
software-only timeout evidence may remain diagnostic but cannot silently
satisfy an IRQ or hardware-acknowledgement requirement.

## Linearization, lock, IRQ, and SMP obligations

Before the SMP implementation begins, the successor specification and an
implementation mapping document must freeze each abstract operation, its
production source, lock/IRQ context, memory-ordering edge, and visible result.

At minimum, the implementation must establish:

| Boundary | Required winner or ordering |
| --- | --- |
| `Register` / `Derive` | root gate validation, ancestry insertion, credit reservation, and all reverse-index memberships are one failure-atomic result |
| `Commit` / `RevokeBegin` | one total winner for the same root; an old uncommitted effect cannot publish after revoke wins |
| crash / service operation | binding advance fences every CPU; stale prepare, commit, reply, and adopt reject without mutation |
| `Adopt` / kernel abort | one winner for each eligible orphan; adoption changes current binding only |
| queue preparation / device commit | descriptor and DMA initialization happen-before `avail.idx` Release; notification happens after commit |
| completion / cancel / reset | one terminal disposition; an old completion cannot resurrect or republish an effect |
| data publication / guest reply | backend data becomes valid before the one-shot reply; a crash between them preserves the committed obligation |
| reset acknowledgement / generation advance | generation changes only after the selected reset authority is consumed |
| IOMMU completion / frame reuse | invalidation completion happens-before owner and frame release on every CPU |
| `RevokeNext` / index removal | each selected effect leaves each live reverse index exactly once |
| `RevokeComplete` | all frozen effects terminal or honestly retained as required, no pending publication, and the selected credits have their required disposition |

The implementation must document a lock order and demonstrate that it is
followed by normal, recovery, closure, and interrupt paths. It must not hold a
spin lock across a blocking wait. A lock reachable from a local interrupt must
either exclude that interrupt while held or use a documented non-reentrant
scheme. Cross-CPU epoch and receipt publication requires explicit
release/acquire or stronger ordering; volatile access and compiler ordering are
not substitutes.

The SMP gate must exercise actual OSTD synchronization. Loom models should use
the same production transition functions where feasible and may abstract the
outer lock, but their accepted wording must not be used to claim that OSTD
`SpinLock`, IRQ masking, or SMP execution was checked. Static source mapping,
Loom, and actual SMP execution are separate evidence layers.

No lock-freedom or starvation-freedom claim is required. Any bounded-progress
claim must name the fairness, watchdog, device, and scheduler assumptions that
make it meaningful.

## Fault-injection contract

Fault injection is part of the implementation architecture. The exact matrix
and cardinality must be frozen in machine-readable form before the final
implementation run. Every cell must execute through the normal production path
and the same shared root registry/ledger.

Required fault families include:

- derive/register versus root revoke;
- allocation or validation failure before a multi-object transition;
- crash before device commit;
- crash after device commit but before backend completion;
- crash after backend completion but before guest reply;
- stale old-binding prepare, commit, completion, reply, and adopt attempts;
- adopt versus kernel abort;
- duplicate and replayed commit, publication, completion, reset, IOMMU, and
  closure receipts;
- device completion versus reset acknowledgement;
- reset timeout followed by retry;
- IOMMU timeout followed by late acknowledgement and retry;
- repeated service crash before and after rebind;
- root revoke while an IRQ/completion executes on another CPU;
- wrong registry instance, root, effect, queue, device session, generation, or
  ancestry;
- resource pressure while a tombstone retains queue, DMA, or frame credit.

Each cell must record the injection point, CPU, complete presented identity,
expected and observed result, before/after semantic projection, terminalization
count, publication count, credits before and after, retained owners, final root
state, and whether a non-success timeout is honest. Negative operations must be
checked for complete failure atomicity rather than only for an error code.

The verifier must include source and mutation gates that reject dropped,
duplicated, reordered, fabricated, or bypassed cells and assertion markers. A
hard-coded result table is not runtime evidence.

## 2-vCPU and 4-vCPU acceptance

The same successor semantics and workload must pass separate 2-vCPU and 4-vCPU
gates. The contract must pin QEMU/OSTD versions, CPU model, accelerator,
interrupt mode, device configuration, IOMMU configuration, affinity policy, and
timeout policy.

The executions must force meaningful cross-CPU interaction rather than merely
booting additional idle CPUs. At minimum they must place root revocation,
service execution/recovery, and device completion or IRQ handling on distinct
CPUs in one or more controlled schedules. The 4-vCPU gate must include a
schedule in which these three responsibilities are concurrently runnable.

Acceptance requires:

- all required deterministic schedules and predeclared stress seeds complete;
- the real OSTD lock and IRQ paths are used;
- every accepted transition maps to the successor specification;
- no stale commit, duplicate terminalization/publication, credit
  duplication/loss, early owner release, index resurrection, or cross-root
  receipt acceptance occurs;
- watchdog expiry returns a named non-success state when closure cannot be
  established; it never fabricates `Revoked`;
- repeated runs retain the complete logs and raw failure artifacts;
- the result passes on both CPU counts. Passing only one count is a bounded
  partial result, not `v0.2.0` acceptance.

Random stress is supplemental. At least one deterministic schedule must cover
each critical winner, and the exact seed set and repetition count must be fixed
before the release run.

## Measurement and baselines

Correctness and performance evidence are separate. TCG may remain useful for
deterministic fault schedules, but performance claims require KVM or a named
physical machine with an invariant clock or hardware performance-counter
protocol.

The measurement contract must be committed before the final data is collected.
It must define warmups, sample counts, outlier policy, CPU isolation, frequency
policy, cache state, confidence interval or descriptive statistics, and every
operation included in or excluded from an interval. Raw samples and environment
metadata must be retained.

At least these baselines are required:

1. **normal-path compatibility baseline:** the same block-backed read on the
   same kernel/device path with CSER effect tracking disabled or bypassed only
   for a no-failure measurement. This baseline has weaker semantics and must not
   be used in a fault comparison;
2. **epoch-only baseline:** the same normal operation with authority/binding
   validation but without causal reverse-index closure and typed-resource
   accounting, where an honest implementation is feasible;
3. **closure-structure baseline:** a deliberately global-scan implementation or
   evaluator over the same population, used only to compare target-local versus
   unrelated work;
4. **CPU-count baseline:** the accepted CSER path on 1, 2, and 4 vCPUs under the
   same named workload and affinity policy.

Required measurements include:

- steady-state read latency and throughput;
- `Register`, `Prepare`, `Commit`, completion, publication acknowledgement, and
  terminalization cost;
- memory and index bytes per live and retained effect;
- `RevokeBegin` versus total population `N`;
- complete closure versus target cohort `k` and retained history;
- crash-to-fallback, replacement-ready, adoption, and guest-resume latency;
- lock contention and cross-CPU scaling;
- reset/IOMMU timeout retention and successful-retry latency;
- resource pressure while tombstones retain owners.

Numerical thresholds, if used as release gates, must be justified and frozen
before the final measurement run. A threshold selected after observing the
release data is descriptive, not an acceptance criterion. A reproducible high
overhead result may still be a valid negative research result, but it cannot be
described as low overhead.

## Related-work gate

The related-work track runs before and alongside implementation. It is not a
post-hoc section written after the desired claim is chosen.

Before the identity-preserving implementation is treated as a contribution
candidate, the project must:

- obtain and audit the full primary text for the current Shadow Drivers and
  Atomic RPC metadata-only rows, or retain an explicit unresolved exclusion;
- perform backward and forward citation tracing from the closest capability,
  restartable-service, OS-transaction, device-recovery, exactly-once, and
  effect-authority work;
- compare each close system on authority propagation, asynchronous-effect
  identity, commit/linearization gate, crash/rebind fencing, resource
  accounting, post-commit disposition, device quiescence, multi-service
  composition, and evaluation boundary;
- distinguish standardized or deployed mechanisms such as capability revoke,
  asynchronous cancellation, fencing tokens, VirtIO reset, and IOMMU teardown
  from the particular interaction this RFC proposes to test;
- write one falsifiable contribution delta and at least one result that would
  refute it before the final implementation/evaluation gate.

Until this gate passes, the project may describe the work only as a prospective
combination or replication study. `Novel`, `first`, and `proved` remain
forbidden release claims regardless of implementation success.

## Kill and pivot criteria

This RFC is a research gate, not a commitment to finish a predetermined feature.
The current direction must stop, be revised in the specification, or be
explicitly reframed as a negative/replication result if any of the following
holds:

1. a reachable execution permits an old uncommitted effect to publish after
   `RevokeBegin`, duplicates terminalization or publication, copies typed credit,
   or releases a possibly DMA-visible owner before acknowledged teardown;
2. the same root/effect/device identity cannot cross the actual filesystem and
   VirtIO/IOMMU path without trusted reconstruction or a synthetic cohort;
3. failure atomicity requires a hidden side ledger, unvalidated trace repair, or
   a fallible partial mutation that cannot be made retryable;
4. no documented lock/IRQ scheme can provide a total Commit/Revoke winner and
   safe completion/reset ordering on 2 and 4 vCPUs;
5. deterministic SMP schedules repeatedly hang, leak, resurrect an index entry,
   or violate the semantic projection, and the fix would invalidate the stated
   mechanism rather than refine it;
6. the pinned platform cannot expose the same-boot real device, interrupt, and
   IOMMU acknowledgement path required by the experiment;
7. predeclared measurements show that the selected design has unacceptable
   scaling or overhead for the stated hypothesis and no bounded redesign remains
   to test;
8. full-text related-work review shows that the claimed interaction and evidence
   have already been established with no material distinction;
9. the evidence cannot be reproduced from a clean source revision or cannot be
   bound to one source/run identity.

A kill criterion is not permission to hide the counterexample. The failure
trace, affected claim, and pivot decision should become part of the artifact.
Safety failures block a positive release claim. Performance or prior-art
failures may support a carefully framed negative result.

## Phased evidence plan

Each phase starts with a committed acceptance contract and ends with source-bound
evidence. A later phase may consume an earlier accepted receipt, but it may not
rewrite the earlier semantics or copy an artifact into a new run identity.

### Phase 0 — claim and prior-art preflight

- freeze this RFC's hypothesis, non-goals, vocabulary, and kill criteria;
- complete the related-work gate or record its exact unresolved exclusions;
- freeze the first workload, comparison baselines, and preliminary fault
  families;
- decide whether the work remains a plausible systems-mechanism study before
  undertaking the device/SMP implementation.

Exit: a documented `go`, `narrow`, `pivot`, or `stop` decision. No implementation
claim is produced.

### Phase 1 — successor semantics and independent oracle

- add a successor specification for one dynamic root tree, shared service
  bindings, shared typed ledger, the block-read graph, same-effect device
  tombstone, and 2/4-CPU-relevant abstract winners;
- add an independent safe-Rust oracle and negative identity substitutions;
- freeze the abstract-to-production transition map and exact fault matrix;
- check finite safety, reachability, and conditional progress only under named
  bounds.

Exit: `Specified` and bounded `Checked` semantics only. No OSTD, SMP, device, or
performance result is implied.

### Phase 2 — shared production registry and block-read preparation slice

- implement registry-native per-domain bindings and one root typed ledger;
- route the real personality/filesystem request through the shared registry to
  the block-portal preparation boundary;
- preserve immutable ancestry and exact receipts through crash/rebind/adopt;
- bind guest, block image, payload, and implementation artifacts by digest;
- prove the no-synthetic-cohort rule with positive and negative oracles.

Exit: bounded single-CPU `Observed` identity evidence through block preparation.
An abstract or deterministic block adapter in this phase does not satisfy the
accepted block-backed workload, same-boot device, or SMP gates.

### Phase 3 — same-boot device and failure atomicity

- run the real VirtIO/IOMMU request inside the primary workload boot;
- preserve the same root/effect/device identities across commit, completion,
  reset, IOMMU invalidation, tombstone, and retry;
- exercise every frozen fault cell through the shared production registry and
  ledger;
- check cross-object before/after projections and retained owners.

Exit: bounded same-boot `Observed` device evidence and implementation-level
fault checks. It does not yet imply SMP acceptance.

### Phase 4 — real lock/IRQ/SMP refinement

- document and implement the production lock hierarchy, IRQ exclusion, and
  memory-ordering edges;
- rerun model-based concurrency harnesses against the mapped transition source;
- pass the deterministic and stress contracts on both 2 and 4 vCPUs;
- retain all raw schedules, CPU assignments, traces, and failure artifacts.

Exit: the exact SMP safety wording authorized by the accepted contract. It must
not be widened to lock freedom, hardware-general liveness, or all OSTD behavior.

### Phase 5 — measurement and contribution decision

- run every predeclared baseline and measurement population on the named
  hardware/KVM boundary;
- recompute statistics from retained raw samples;
- rerun the complete related-work validator;
- decide `support-bounded`, `narrow`, `reject`, or an explicitly defined
  negative/replication outcome from the evidence and kill criteria;
- write the human claim ledger with evidence, boundary, and non-claim in the
  same row.

Exit: a prospective `v0.2.0` research result. A positive contribution verdict is
not required for the phase to be scientifically complete.

## Release and evidence rules

A `v0.2.0` release is admissible only if all mandatory phases selected by the
final contract have closed and the release wording matches their exact result.
The release process must preserve the existing repository discipline:

1. formal semantics, independent oracle, production implementation, fault
   evaluator, measurements, and related-work decision remain separately
   identifiable evidence layers;
2. the public workflow deletes stale expected evidence before a full run and
   binds the clean source revision, source fingerprint, invocation, cold-rebuild
   state, run nonce, receipts, and every artifact digest;
3. a clean cold local verification and exact pushed-revision CI both pass;
4. 1-vCPU diagnostic evidence cannot satisfy 2-vCPU or 4-vCPU requirements;
5. separate-boot Stage 5B evidence cannot satisfy the same-boot identity gate;
6. case-local or synthetic evaluator ledgers cannot satisfy the shared
   production-registry fault gate;
7. failure artifacts remain diagnostic and cannot be assembled into a success
   manifest by focused commands;
8. the release bundle contains the complete accepted population, raw
   measurements, environment metadata, negative-oracle results, claim ledger,
   and exact verification instructions;
9. the release tag points to the exact revision in the manifest and is not moved
   or retroactively rewritten;
10. `v0.1.0` artifacts, tag, DOI, and claims remain immutable historical results.
11. the formal verifier is recoverable from repository-owned exact bytes, its
    provenance and license travel with the bundle, and a same-container runtime
    receipt binds the installed JAR identity to the model/spec receipt chain.

If only an intermediate phase closes, the project may publish a clearly named
development or negative artifact, but it must not call it `v0.2.0` acceptance or
inherit claims from later phases.

## Acceptance summary

The proposed result is positive only if one accepted evidence chain establishes
all of the following together:

- one real workload-created root and no synthetic replacement cohort;
- registry-native service bindings and one shared typed ledger;
- immutable effect ancestry and exact receipt provenance;
- one block-backed read whose bytes traverse same-boot VirtIO/IOMMU;
- honest reset/IOTLB timeout retention and identity-preserving retry;
- failure-atomic normal, recovery, and closure transitions;
- real OSTD lock/IRQ execution on both 2 and 4 vCPUs;
- predeclared baseline measurements with raw data;
- a completed related-work and contribution decision;
- a clean, exact-revision, reproducible release bundle.

Any missing item remains an explicit exclusion. This RFC does not authorize
prose to infer it from adjacent component evidence.
