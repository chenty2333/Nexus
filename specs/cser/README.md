# CSER executable specification

This directory fixes the first finite-state semantics for Causally Scoped
Effect Revocation (CSER). `Cser.tla` contains both the readable PlusCal source
and its generated TLA+ transition relation. `CserMC.cfg` is the bounded model
used for the checked result below.

This is a protocol model, not a claim that an already submitted device effect
can be rolled back. `Committed` is the abstract point after which a concrete
backend must complete, drain, reset, or retain a tombstone.

`PagerCser.tla` and `PagerCserMC.cfg` are the Stage 4 successor refinement for
one address-space pager scope. They add one-shot fault continuations, a distinct
address-space generation, prepared-frame ownership, same-page publication,
crash/rebind/adopt, and a kernel-owned recovery deadline. The exact pager
semantics, checked properties, finite boundary, and TLC result are documented
in `PAGER.md`; they extend rather than replace the baseline model below.

`IoCser.tla`, `IoCserSafetyMC.cfg`, and `IoCserMC.cfg` are the Stage 5 successor
refinement for one scope that exclusively owns a split VirtIO block queue and
device. They fix the `avail.idx` Release publication as the request commit
point and model service crash/rebind/adopt, device-generation completion
fencing, whole-device reset, per-request and queue DMA invalidation, honest
timeout tombstones, retry, and conditional quiescent closure. The 3-ID safety
configuration uses request symmetry but no temporal checking; the smaller
action/liveness configuration deliberately runs without symmetry. `IO.md`
documents the split, reachability witnesses, precise outcomes, and model
boundary. This refinement does not claim that an already published write can
be rolled back or that the real OSTD/IOMMU path is already complete.

`PersonalityCser.tla`, `PersonalityCserSafetyMC.cfg`, and
`PersonalityCserMC.cfg` are the bounded Stage 6A refinement for a restartable
Linux personality. They separate a `write` backend commitment from the later
one-shot guest reply, give `exit_group` a process-exit terminal outcome with no
resume, and model crash, fallback, exact orphan snapshot, ready/rebind,
explicit adoption, old-binding rejection, and authority closure. The safety
configuration uses two syscall IDs with symmetry; the action/liveness
configuration uses one ID without symmetry. `PERSONALITY.md` records the
semantics, coverage witnesses, checked results, and deliberately narrow model
boundary. It is not a claim of general Linux compatibility.

`PersonalityFutexCser.tla`, `PersonalityFutexCserSafetyMC.cfg`, and
`PersonalityFutexCserMC.cfg` are the Stage 6B.1 successor refinement. They keep
Stage 6A unchanged while adding one private futex key, one wait and one wake,
compare/register, frozen wake selection and count, kernel wake publication,
crash/rebind/adopt, a CSER recovery watchdog, wait/wake/timer credit
conservation, and wake/revoke ordering. The watchdog never becomes a Linux
futex timeout. `PERSONALITY_FUTEX.md` records the Rust refinement mapping,
reject-enabled action check, reachability witnesses, complete TLC results, and
the explicit exclusion of requeue, multiple waiters/keys, SMP, and concrete
implementation details from the formal model. Together with the pure Rust
successor, these artifacts complete the Stage 6B.1 semantics checkpoint.

`PersonalityFutexRequeueCser.tla`, its safety/action configurations, and
`PERSONALITY_FUTEX_REQUEUE.md` are the bounded Stage 6B.2 two-key successor.
They separate immutable origin-key identity from mutable current queue
membership and check an atomic wake/move partition, Linux's total affected
count, current-binding queue-head fencing, typed-credit preservation, both
revoke orders, and target-key wake after migration. The full safety graph has
4,786,581 generated / 1,927,174 distinct states at depth 27; the action graph
has 247,047 generated / 140,473 distinct states at depth 23, with four
temporal branches and six reachability witnesses. It remains a bounded private
futex protocol, not a general or SMP Linux futex implementation.

`PersonalityReadinessCser.tla`, its two configurations, and
`PERSONALITY_READINESS.md` fix the reusable readiness/positive-timeout
protocol below epoll-like ABIs. They check atomic sample-and-arm,
LT/ET/ONESHOT discipline, one immutable ready/timeout publication, a unique
ready/timeout/revoke winner, source-generation fencing, exact crash recovery,
and typed-credit closure. The complete safety graph has 83,586 generated /
50,544 distinct states at depth 20; the action graph has 55,569 generated /
34,428 distinct states at depth 19, with three temporal branches and eight
reachability witnesses.

`PersonalityExecCser.tla`, its two configurations, and
`PERSONALITY_EXEC.md` fix failure-atomic executable-image replacement. Staged
segments and frozen TLS/stack layout remain invisible until one `ExecCommit`
publishes the complete image. Pre-commit revocation preserves the old image;
post-commit revocation drains without rollback. The complete safety graph has
361 generated / 253 distinct states at depth 15; the action graph has 182
generated / 137 distinct states at depth 14, with three temporal branches and
six reachability witnesses.

`RuntimeFsCser.tla`, its safety/action configurations, and `RUNTIME_FS.md`
fix the bounded runtime-filesystem successor across independently restartable
personality, pager, filesystem, and block domains. The model separates pager
mapping, inode-write, block `avail.idx`, and guest-reply publication points;
tracks authority, binding, address-space, inode, and device generations; and
retains DMA ownership through reset/IOTLB timeout tombstones and retry. Its
reject-enabled safety graph has 2,262,368 generated / 635,313 distinct states
at depth 35; its action graph has 80,108 generated / 44,768 distinct states at
depth 29. Eight required witnesses cover both revoke/write orders, three
service-recovery cases, both timeout stages, and all stale-token fences. This
is a finite protocol model, not a filesystem, block driver, or DMA proof.

`RuntimeNetCser.tla`, its safety/action configurations, and `RUNTIME_NET.md`
fix the bounded runtime-network successor across independently rebound
personality, network, and readiness domains. The fixed causal graph is
`Root -> Syscall -> NetOperation -> {ReadinessWait, BufferLease}`; Control,
Network, Readiness, and Buffer credits are distinct, as are `NetCommit`,
`ReadyCommit`, and the later guest reply. Its reject-enabled safety graph has
3,698,288 generated / 720,002 distinct states at depth 42; its action graph has
28,449 generated / 14,328 distinct states at depth 35. Eight temporal branches
and eight independent reachability witnesses cover publication/revoke orders,
network-service crash/adopt, readiness/revoke orders, personality crash
drain/abort, retained-buffer visibility, and stale-token fencing. This is a
finite in-memory loopback protocol, not a TCP/IP stack, socket ABI, VirtIO-net,
NIC, external-packet, or SMP proof.

`CompositionCser.tla`, its safety/action configurations, and `COMPOSITION.md`
fix the bounded Stage 6C system-wide composition contract across scheduler,
pager, personality, readiness, and VirtIO domain registries. One root authority
scope owns immutable cross-domain parent edges and typed root-ledger delegation
while each domain retains an independent binding epoch; VirtIO additionally
retains an independent device generation. Root revocation freezes the exact
participating-domain cohort, requires unique domain closure receipts, and
allocates every timeout/closure receipt from one global monotone sequence. It
cannot hide a timed-out VirtIO tombstone or accept its stale receipt after
retry. The complete safety and action graphs each have 1,236,504 generated /
965,051 distinct states at depth 31; the action configuration checks six
temporal branches and the script requires four reachability witnesses. This
finite model does not prove arbitrary DAGs, runtime filesystem/network
composition, parent-owned credit partitions, or asymptotic work
proportionality. Its receipt remains frozen with `runtime_fs=false` and
`runtime_net=false`; neither the separate runtime successors nor the additive
seven-domain successor below retroactively widen it.

`LinuxIoCompositionCser.tla`, its safety/action configurations, and
`LINUX_IO_COMPOSITION.md` add the bounded seven-domain Linux I/O composition
successor. One root authority owns nine effects across Scheduler, Pager,
Personality, Filesystem, VirtIo, Network, and Readiness. The model composes the
filesystem and network publication boundaries, independently fenced bindings
and resource generations, eight typed credit classes, root-ordered closure
receipts, VirtIO reset/IOTLB tombstone recovery, and predicate-gated stale
input audits. An explicit five-scenario state-space quotient preserves the
named derive, mixed-I/O, new-domain crash, DMA-timeout, and reject evidence; it
does not claim the abandoned all-feature Cartesian product. The reject-enabled
safety graph has 3,723,455 generated / 1,225,367 distinct states at depth 55.
The same traversal checks all ten action properties. Kernel-closure liveness
checks the three non-vacuous closure partitions as one temporal branch over
1,828,175 generated / 603,886 distinct states at depth 46; crash-fallback
liveness separately checks both crash targets as two temporal branches over
163 generated / 121 distinct states at depth 21. The script additionally
requires ten reachability witnesses, restricted to their disjoint initial-state
partitions; five Core witnesses share one complete traversal with an exact-name
result gate. This remains bounded protocol evidence, not an arbitrary-graph,
all-domain-crash, SMP, filesystem, network-stack, hardware, scale, or
performance proof.

`ProductionIdentityCser.tla`, its two-/four-CPU-actor safety, action, and
conditional-progress configurations, and `PRODUCTION_IDENTITY.md` add the
prospective RFC-0001 formal successor without changing any accepted `v0.1.0`
family. Six workload-created effects form the fixed dynamic tree
`PersonalitySyscall -> FilesystemRead -> BlockRequest -> three DMA owners` in
one registry-native binding table and shared typed ledger. The model checks
immutable ancestry, filesystem crash/rebind/adopt, the device Commit/Revoke
winner, separate guest reply, same-effect reset/IOMMU tombstone retry,
child-first receipts, and failure-atomic foreign-registry/stale-generation
rejection. Its complete two- and four-CPU-actor safety graphs and action graph
each have 4,793 generated / 3,396 distinct states at depth 33. The conditional
progress graph has 3,356 generated / 2,670 distinct states at depth 32 and five
temporal branches; eight witness traversals cover the seven named witness
families at the required CPU counts. CPU values are abstract actor identities,
not OSTD-lock, IRQ, memory-ordering, or real SMP evidence. This successor is a
prospective specification, not an implementation or a widened `v0.1.0` claim.

The independent pinned OSTD/QEMU refinement now supplies a bounded
implementation observation for the same one-key contract. Its `recover` path
observes mismatch-without-registration, atomic compare/enqueue, a real
personality fault, binding-epoch fencing, explicit adoption, watchdog
cancellation, frozen wake commitment, post-revoke stale-authority rejection,
and one waiter/waker publication. Its `expire` path observes an uncommitted wake
losing to watchdog-driven `RevokeBegin`, failure-atomic stale rejection, two
kernel abort terminalizations, and full wait/wake/timer-credit return without
fabricating a Linux timeout. This records Stage 6B.1 as **semantics complete and
bounded OSTD/QEMU slice complete / Observed**. It does not run the retained full
Round 4 program, add requeue/clone/mmap/thread-exit, prove lost-wakeup or SMP
ordering, or establish a common registry. Those statements remain the exact
boundary of the frozen predecessor. The separate Stage 6B.2 successors add a
personality-local common registry, bounded two-key requeue, readiness, and exec
semantics plus independent OSTD/QEMU receipts. They do not establish a registry
shared with scheduler, pager, mediated I/O, filesystem, or network services;
the later runtime-filesystem successor is separate from those frozen
predecessors. The runtime-network successor likewise adds only separate bounded
formal, safe-Rust, and OSTD/QEMU evidence. The additive seven-domain formal
successor now composes those Linux I/O branches without changing the frozen
predecessor receipts; its corresponding safe-Rust/OSTD composition evidence
and the other Stage 6 acceptance obligations remain separate facts.

## Linearization contract

The scope state machine is:

```text
Active --RevokeBegin--> Closing --RevokeComplete--> Revoked
```

`RevokeBegin` is atomic. It snapshots the effects already committed, records
the closing authority epoch, advances the current epoch, and changes the scope
to `Closing`. That single step closes the old epoch's commit gate.

An effect state machine is:

```text
Unregistered -> Registered -> Prepared --Commit--> Committed -> Completed
                    |            |                     |
                    +------------+-> Cancelling        +-> Draining
                                          |                   |
                                          v                   v
                                       Aborted             Completed
```

`Commit` is atomic and is the only transition into `Committed`. It requires
all of the following at the same state:

- the scope is `Active`;
- the supervisor is alive;
- the effect is `Prepared`;
- the effect authority epoch equals the current scope epoch;
- the effect binding epoch equals the current supervisor binding epoch.

`Complete` is normal post-commit completion. During revocation, each
`RevokeStep` advances exactly one live effect: uncommitted effects pass through
`Cancelling` to `Aborted`, while committed effects pass through `Draining` to
`Completed`. `RevokeComplete` is enabled only after every effect in the closing
epoch is terminal.

## Crash and rebind

`Crash` advances the binding epoch atomically, fences replies from the failed
binding, and changes scheduler fallback from `Standby` to `Required`.
`FallbackPick` is the kernel-owned action that changes it to `Running`. The
PlusCal process for this action is weakly fair; no environment action is given
a fairness assumption. Crash is an active-supervisor binding event and is
enabled only in an `Active` scope. If `RevokeBegin` wins their race, crash is no
longer a protocol action and kernel-owned closure proceeds without starting a
new binding lifecycle.

`Rebind` represents completion of the replacement supervisor's snapshot/ready
handshake. It cannot happen before fallback is `Running`, and fallback remains
active until this linearization point. Rebind is permitted only while the scope
is still `Active`; a crash followed by `RevokeBegin` can still run fallback but
cannot resurrect a supervisor in a `Closing` or `Revoked` scope. `Adopt` is
explicit and is limited to an orphan effect that:

- is still `Registered` or `Prepared`;
- belongs to the current authority epoch;
- has an old binding epoch;
- is in an `Active` scope with a live replacement supervisor.

An effect cannot be adopted after `Commit` or after `RevokeBegin`.

## Checked properties

`CserMC.cfg` checks:

- `TypeOK`: every state remains inside the finite model domains;
- `BudgetStateConsistency`: every effect state agrees with whether its budget
  is held, spent, returned, or unused;
- `PostRevokeCommitExclusion`: no old-epoch effect first commits after
  `RevokeBegin`;
- `QuiescentClosure`: `Revoked` implies every closing-epoch effect is terminal
  and owns no held credit;
- `SingleTerminalization`: each effect reaches `Completed` or `Aborted` at
  most once;
- `OldBindingCannotCommit`: a fenced binding cannot cross `Commit` unless an
  uncommitted effect is first adopted into the current binding;
- `BudgetConservation`: `free + held + spent = TotalBudget` in every state;
- `SchedulerFallbackProgress`: under weak fairness, `Required ~> Running`.

The budget is an abstract consumable credit. `Register` moves one credit from
`free` to `held`; `Commit` moves it from `held` to the accounted `spent` ledger;
an abort returns it from `held` to `free`. A concrete renewable resource can
add a later replenishment transition without weakening the no-duplication
invariant.

## Trace vocabulary

Implementations and counterexample exporters use these exact action names:

```text
Register Prepare Commit Complete RevokeBegin RevokeStep RevokeComplete
Crash Rebind Adopt FallbackPick
```

The common event fields are `seq`, `scope`, `effect`, `authority_epoch`,
`binding_epoch`, `from`, `to`, and `outcome`. The finite TLA+ state keeps only
the history needed by the invariants instead of an unbounded event log.

## Run the specifications

The accepted `v0.1.0` repository entry point uses the pinned Docker image,
verifies its checked-in PlusCal translations, runs its twelve TLC model
families in order—baseline, pager, mediated I/O, Linux personality, private
futex, two-key futex requeue, readiness, exec, runtime filesystem, runtime
network, five-domain composition, and seven-domain Linux I/O composition—and
writes separate logs under `target/verification/`:

```sh
./x spec
```

Inside the pinned development container, the lower-level script uses the
checked TLA+ tools jar:

```sh
TLA2TOOLS_JAR=/path/to/tla2tools.jar ./specs/cser/check.sh
```

These commands describe implementation steps inside the container; they do not
define a second supported host toolchain. The directory-local `check.sh` now
checks the twelve frozen families plus the prospective production-identity
successor when invoked without an argument. The root `./x spec` catalog remains
the accepted twelve-family `v0.1.0` boundary until a later repository-wide
version deliberately admits the successor. Pass `Cser`, `PagerCser`, `IoCser`,
`PersonalityCser`, `PersonalityFutexCser`,
`PersonalityFutexRequeueCser`, `PersonalityReadinessCser`,
`PersonalityExecCser`, `RuntimeFsCser`, `RuntimeNetCser`, `CompositionCser`, or
`LinuxIoCompositionCser` to run one frozen family; pass
`ProductionIdentityCser` to run only the prospective successor.

The independent prospective gate checks translation drift, all four complete
graphs, and the exact ordered eight-witness population, then writes a receipt
under `target/research/production-identity/` without adding artifacts to the
accepted `v0.1.0` manifest or bundle:

```sh
./x research production-identity
```

To modify an algorithm, edit only its PlusCal block and regenerate the
translation before checking:

```sh
cd specs/cser
java -cp "$TLA2TOOLS_JAR" pcal.trans -nocfg -lineWidth 1000 Cser.tla
java -cp "$TLA2TOOLS_JAR" pcal.trans -nocfg -lineWidth 1000 PagerCser.tla
java -cp "$TLA2TOOLS_JAR" pcal.trans -nocfg -lineWidth 10000 IoCser.tla
java -cp "$TLA2TOOLS_JAR" pcal.trans -nocfg -lineWidth 1000 PersonalityCser.tla
java -cp "$TLA2TOOLS_JAR" pcal.trans -nocfg -lineWidth 10000 PersonalityFutexCser.tla
java -cp "$TLA2TOOLS_JAR" pcal.trans -nocfg -lineWidth 10000 PersonalityFutexRequeueCser.tla
java -cp "$TLA2TOOLS_JAR" pcal.trans -nocfg -lineWidth 10000 PersonalityReadinessCser.tla
java -cp "$TLA2TOOLS_JAR" pcal.trans -nocfg -lineWidth 10000 PersonalityExecCser.tla
java -cp "$TLA2TOOLS_JAR" pcal.trans -nocfg -lineWidth 10000 RuntimeFsCser.tla
java -cp "$TLA2TOOLS_JAR" pcal.trans -nocfg -lineWidth 10000 RuntimeNetCser.tla
java -cp "$TLA2TOOLS_JAR" pcal.trans -nocfg -lineWidth 10000 CompositionCser.tla
java -cp "$TLA2TOOLS_JAR" pcal.trans -nocfg -lineWidth 10000 LinuxIoCompositionCser.tla
java -cp "$TLA2TOOLS_JAR" pcal.trans -nocfg -lineWidth 10000 ProductionIdentityCser.tla
```

The baseline `CserMC.cfg` instance uses three effect identifiers, two total
credits, and at most two crash generations. The extra identifier exercises a
failed registration opportunity while all credits are held or spent. With
`tla2tools.jar` 1.8.0 it completes the full state graph with no error; the
successor results are recorded separately in `PAGER.md`, `IO.md`,
`PERSONALITY.md`, `PERSONALITY_FUTEX.md`,
`PERSONALITY_FUTEX_REQUEUE.md`, `PERSONALITY_READINESS.md`,
`PERSONALITY_EXEC.md`, `RUNTIME_FS.md`, and `RUNTIME_NET.md`, with the
composition successors recorded separately in `COMPOSITION.md` and
`LINUX_IO_COMPOSITION.md`; the prospective successor is recorded in
`PRODUCTION_IDENTITY.md`:

```text
11,122 states generated
5,457 distinct states found
0 states left on queue
complete graph depth 19
```

`CHECK_DEADLOCK` is disabled because a quiescent `Revoked` state is a valid
protocol outcome; TLA+ permits stuttering there.

## Model boundary

The bounded instance has one scope generation, one-shot effect identifiers,
unit-sized budget credits, and bounded supervisor generations. It deliberately
does not model effect payloads, real time, device-specific quiescence, nested
scope lineage, or resource replenishment. Those refinements should preserve
the checked linearization points and invariants rather than silently changing
their meaning.
