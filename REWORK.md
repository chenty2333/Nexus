# Nexus rework ledger

This ledger records what survives the CSER reset. It is a deletion plan, not a
promise to preserve the current Axle/Zircon/Starnix architecture.

The current research checkpoint consists of the baseline CSER state machine,
its pager refinement, the pure Rust reference oracles, the OSTD/OSDK feasibility
spike, the scheduler crash-to-fallback slice, and one bounded pager
crash/rebind/timeout slice. Stage 5 now also has a checked mediated-I/O protocol
and safe-Rust oracle plus one bounded, one-page patched-OSTD IOTLB-ownership
receipt. Stage 5B adds a bounded real-device receipt for mediated readonly
VirtIO, reset/tombstone recovery, and three-owner IOTLB closure. Stage 6A adds
the bounded personality spec/oracle, one static `linux-hello` execution, and two
same-implementation companion personality-closure scopes. Stage 6B.1 now adds
a checked private-futex TLA+ successor, pure Rust oracle, and bounded OSTD/QEMU
wait/wake recovery slice. Stage 6B.2 adds the personality-local common effect
registry, two-key requeue, readiness, and failure-atomic exec successors plus
pinned QEMU receipts for adapted Round 4 futex, adapted Round 5 epoll, and
retained dynamic PIE. Four of six bounded Linux core inputs are now Observed;
runtime filesystem, runtime network, and the Linux pressure program remain
incomplete. A separate system-composition checkpoint now adds the bounded
five-domain TLA+/Rust/Loom successor, one OSTD root-authority receipt, and a
strict two-log component-consistency check against the existing Stage 5B
VirtIO/DMA receipt.
The pager, device, and Linux results are not a production pager, I/O subsystem,
futex registry, or Linux personality. The foundation decision is **OSTD-first**, not
irrevocably OSTD-only: if a documented critical boundary cannot be fixed by an
upstream API or a small audited adapter/patch without violating single-owner
hardware control, Nexus must re-evaluate the foundation explicitly. That
decision still must not pull in a legacy crate merely because it already
exists.

## Status vocabulary

- **KEEP**: this is a current source of truth or a deliberately retained test
  input. It stays maintained.
- **MIGRATE**: preserve a narrowly named contract, race, workload, or tool
  capability in the new tree, then delete the original.
- **REWRITE**: replace the subsystem behind the new OSTD/CSER boundary. Source
  code is not carried forward unless a separate MIGRATE row names the asset.
- **DELETE**: remove after its remaining build dependencies are detached. Git
  history is the archive.

`MIGRATE` never means that legacy behavior becomes normative. The normative
CSER semantics live in `specs/cser/`; migrated legacy cases are regression
questions that a new implementation may deliberately answer differently.

## Deletion gates

The legacy implementation may be removed as one large change after all of the
following are true:

1. A root Docker + `./x`/xtask entry point runs formatting, lint, model tests,
   TLC, and the OSTD QEMU slice.
2. CI calls that same entry point and no longer invokes Nix or Just.
3. `specs/oracles/*.toml`, `tests/guest/linux/SOURCES.toml`, and
   `tests/guest/linux/COMPATIBILITY.toml` all parse; their IDs and references
   are coherent; every declared build profile is supported; the source-file
   set is closed; and every retained Linux copy matches its declared SHA-256.
4. The neutral runner can enforce timeouts, ordered/required/forbidden serial
   events, numeric bounds, and failure-artifact retention.
5. Cargo metadata and a repository search show that new CSER/OSTD code has no
   dependency on the legacy Axle/Zircon/Starnix crates.

The old and new trees coexist only until these gates pass. We do not keep a
permanently buildable `legacy/` kernel.

## Phase 0 execution record

The deletion gates were satisfied on 2026-07-11 and the reset was executed as
one repository transaction after a separate build/CI checkpoint:

- root Docker, `./x`, xtask, pinned lockfiles, TLC, and the OSTD QEMU slice all
  passed with runtime networking disabled;
- CI was reduced to the same `./x verify` entry point;
- the oracle catalogs and 34 retained Linux source copies passed schema,
  reference-closure, and SHA-256 validation;
- Nix, direnv, Just, the Axle kernel and crates, Zircon facades, the old
  Starnix-like server, old conformance runner, generated syscall ABI,
  implementation references, and obsolete documentation were removed;
- the root Cargo workspace now contains only `crates/cser-model`; xtask and the
  OSTD experiment remain deliberately isolated workspaces.

Git history, ending with the pre-deletion build checkpoint, is the archive.
Legacy paths that remain below or in oracle catalogs are provenance records,
not live build dependencies. The per-module rows in this ledger record the
decisions that were applied; they do not imply that deleted paths still exist.

## Migration receipts

The following extractions are already present in the new tree:

| Legacy asset | New location | Verification |
| --- | --- | --- |
| wait/timer, fault, revocation, scheduler, and future I/O race questions | `specs/oracles/cser-races.toml` | schema v1 parses; IDs are unique |
| six selected old vertical-slice observations | `specs/oracles/legacy-slices.toml` | schema v1 parses; no legacy build command is retained |
| 34 Linux C/assembly guest inputs | `tests/guest/linux/sources/` | every copy matches both its legacy source and the SHA-256 in `SOURCES.toml` |
| 28 old Linux compatibility scenarios plus one superseded guest input | `tests/guest/linux/COMPATIBILITY.toml` | all source IDs resolve and all 34 copied inputs are referenced; only six `core` workloads are Stage 6 commitments, with the remainder marked `stretch` or `archive-input` |
| bounded Linux pressure inputs | four retained core inputs -> isolated OSTD guest artifacts | Docker builds unchanged `linux-hello`, temporarily adapted Round 4 and Round 5 inputs, and the retained dynamic PIE set; source/patch/adapted/artifact gates and strict QEMU oracles leave only runtime filesystem and runtime network unexecuted |

These receipts do not authorize deletion by themselves; the build, CI, and
neutral-runner gates above must pass in the same cleanup checkpoint.

## Stage 4 bounded pager receipt

The first pager evidence gate is recorded as **bounded slice complete /
Observed**:

- `PagerCser.tla` completed its committed finite graph with no TLC error:
  17,150 generated states, 7,528 distinct states, zero queued states, reported
  depth 17-18 across clean 16-worker runs, and ten temporal-property branches
  checked;
- the safe-Rust pager oracle passed 12 deterministic tests and five proptests,
  each configured for 64 cases;
- four bounded Loom surrogate models passed for commit/timeout,
  adopt/timeout/stale-reply, single wake-authority, and three-stage closure
  publication interleavings;
- pinned QEMU `recover` observed a real client fault, a real pager-v1 fault and
  crash, binding epoch 1 to 2, a fresh pager-v2 `Task`/`VmSpace`/`UserMode`,
  ready/rebind, explicit adoption, one mapping publication, local TLB sync, and
  one successful retry;
- pinned QEMU `timeout` observed `Closing` and reply-gate closure first,
  frame/waker cleanup outside the state lock while credit stayed held, and only
  then credit return plus `Revoked`/`RevokeComplete`.

This receipt does not promote the experiment to a production pager. Its
recovery snapshot is a boolean handshake, stale/pre-rebind rejection uses
kernel predicate probes, and OSTD's reusable `Waker` is fenced by Nexus state
rather than providing one-shot authority. The implementation remains
single-CPU, single-client, zero-page-only, and local-TLB-only; it retains the
documented intermediate-page-table OOM `unwrap`, has no arbitrary task-kill
primitive, and does not cover SMP, multi-client, file-backed, COW, swap, or
durable recovery. Those limits stay live even though the bounded gate allows
work to move to the Stage 5 DMA ownership decision.

## Stage 5A protocol and DMA-ownership receipt

The Stage 5A evidence gate is recorded as **bounded slice complete / Observed**:

- the three-request `IoCser` safety graph completed with 21,998,796 generated
  states, 4,151,240 distinct states, zero queued states, and depth 39; its
  symmetry-enabled graph contains no temporal properties;
- the independent two-request, no-symmetry action/liveness graph completed
  with 1,138,855 generated states, 269,645 distinct states, zero queued states,
  depth 29, and five temporal-property branches;
- explicit expected-counterexample gates witness budget-only registration and
  binding-only stale-publish rejection plus mixed
  `Completed`/`IndeterminateAfterReset` outcomes;
- the safe-Rust I/O oracle covers typed credits, independent generations,
  publication, cancellation, reset/completion races, invalidation, timeout,
  tombstone, retry, and incremental closure ledgers with deterministic,
  property, and bounded Loom tests;
- Nexus selected a small, experiment-local MPL-2.0 OSTD 0.18 patch as the
  prototype's single-owner IOMMU boundary. Pinned QEMU observed one real
  one-page queued global IOTLB invalidation, retained ownership across
  `Pending`, acknowledgement before frame/IOVA/accounting release, and reuse
  only through a fresh identity after completion.

This receipt is deliberately narrower than mediated VirtIO closure. The DMA
probe never exposes its IOVA to a device and records `device_dma=false` and
`device_reset=false`; it is one CPU, one page, and one global invalidation slot.
It does not establish device drain/reset, interrupt quiescence, real deadline
tombstones, SMP liveness, or production domain ownership. The separate Stage 5B
receipt below adds a real device-visible buffer and conditional emulator
`Quiesced`; it does not retroactively widen what Stage 5A alone proved.

## Stage 5B mediated VirtIO receipt

The Stage 5B evidence gate is recorded as **bounded slice complete /
Observed**:

- `virtio-drivers = 0.13.0` is reused without forking for PCI transport,
  `VirtQueue<16>`, and block wire types; Nexus owns only serialized PCI config,
  BAR/DMA owners, the mediation portal, reset/tombstone policy and oracle;
- a pinned QEMU q35 device at `00:05.0` negotiates exactly readonly,
  `VERSION_1`, and `ACCESS_PLATFORM`; one real sector-0 request commits at the
  audited `avail.idx` Release publication, emits one separately observed PCI
  doorbell, traverses three distinct non-identity VT-d IOVAs, completes with
  513 writable bytes and validates the fixed readonly fixture;
- the typed portal rejects a write before any session or queue exists, and the
  receipt proves that effect count and next request identity are unchanged;
- a software-injected reset timeout retains transport, queue, request and two
  queue DMA pages, epochs and generation in a fail-closed
  `ManuallyDrop` tombstone; retry observes real status zero before bus-master
  disable and queue retirement;
- an injected first IOTLB poll retains all three DMA owners; retry observes one
  queued global invalidation and ordered wait descriptor per page before
  backing release;
- generation 2 publishes without notification, crashes binding epoch 2 to 3,
  resets the whole device, and reaches `IndeterminateAfterReset`; stale
  binding/generation completion, a real late-notify attempt, and duplicate
  terminalization are rejected;
- reset and IOTLB acknowledgements are carried by non-forgeable type-state
  tokens; the closure receipt is consumed once when the portal publishes
  `Quiesced`, so it cannot be replayed across generations;
- the first request emits exactly one observed PCI doorbell and queue notify;
  the second emits neither, while both post-reset windows remain free of old
  device activity;
- explicitly enabled negative traces show no block write, backend write or
  VT-d fault, and the fixture SHA-256 is unchanged after QEMU.

This is emulator evidence for one CPU, one exclusive readonly queue, one-page
owners, polling completion, masked INTx, a shared OSTD IOMMU domain and
whole-device reset. Both timeout observations are software injections. It does
not establish physical PCIe drain, IRQ/MSI quiescence, per-device isolation,
multi-page/SMP liveness, irreversible write or network semantics, a real-time
deadline worker, system-wide fault injection or k/N scaling.

## Stage 6A bounded Linux receipt

The first Linux pressure gate is recorded as **bounded slice complete /
Observed**:

- `PersonalityCser.tla` separates `write` backend commitment from guest reply
  and models crash/snapshot/ready/rebind/adopt plus authority closure. Its
  two-ID safety graph completed with 20,478 generated states, 12,802 distinct
  states and depth 20; the independent one-ID action/liveness graph completed
  with 629 generated, 507 distinct and depth 14. Three coverage witnesses
  reached post-commit recovery, single-exit/no-resume, and committed-drain plus
  uncommitted-abort closure;
- the safe-Rust personality oracle passed seven deterministic tests and three
  proptests for full-identity tokens, commit/reply ordering, crash/rebind/adopt,
  revoke races, failure-atomic rejection, and single delivery;
- Docker reproducibly builds the unchanged retained `linux-hello/hello.S` as a
  static x86-64 `ET_EXEC`; the source and generated ELF hashes, W^X, program
  headers, entry and minimal aligned initial stack are gated;
- one workload boot observes a real scheduler-policy fault and first FIFO
  fallback pick, a lazy file-backed instruction fault followed by code-pager
  crash/rebind/adopt and one RX mapping/resume, then Linux `write` and
  `exit_group` dispatch;
- linuxd-v1 publishes the write backend once and faults before guest reply.
  Fresh linuxd-v2 snapshots/rebinds/adopts the committed continuation, receives
  `AlreadyCommitted` on the duplicate backend attempt, and publishes one guest
  reply/resume. Full-token stale/no-supervisor/identity, unknown opcode,
  duplicate adopt/reply, and invalid exit ordering attempts are rejected with
  identical logged semantic projections;
- `exit_group` follows explicit `Captured -> ReplyPrepared -> Completed`,
  publishes one process exit, and never re-enters guest `UserMode`;
- companion scopes 31 and 32 instantiate the same `PersonalityScenario` and
  transition helpers. The former observes revoke-before-commit and one abort;
  the latter observes commit-before-revoke and one kernel drain. Both reject an
  early `RevokeComplete`, reject post-revoke user commit/reply without mutation,
  consume and publish one real OSTD waker, empty their live index, and only then
  reach `RevokeComplete`.

This receipt is not the whole Stage 6 gate. It uses one CPU, fixed enqueue
order, one process/thread, one lazy code page, a single-slot portal, static
`ET_EXEC`, `write(1, ...)`, and `exit_group(0)`. Most linuxd control flow is a
freestanding Rust `global_asm!` dispatch probe; the kernel harness still owns
portal delivery, bounded copy-in and state transitions. Scope 30 is co-tagged
across scheduler, pager and personality but is not itself revoked; the two
closure scopes are personality-only companions, not a unified cross-service
registry. The v1 delayed reply uses a bounded kernel queue, code-pager stale
cases remain predicate probes, and there is no personality timeout/tombstone,
dynamic loader, threads/futex, fd/epoll, filesystem/network, SMP or production
capability implementation. The other five core Linux workloads remain pending.
That sentence records the Stage 6A checkpoint: the Stage 6B.2 receipt below
subsequently closes the bounded futex, epoll, and dynamic PIE inputs, leaving
runtime filesystem and runtime network pending.

## Stage 6B.1 private-futex receipt

This checkpoint is recorded as **TLA+ and Rust semantics complete / bounded
OSTD/QEMU slice complete / Observed**:

- `PersonalityFutexCser.tla` keeps Stage 6A unchanged and checks one private
  key, one waiter, one waker, `max_wake = 1`, crash/rebind/adopt, a CSER recovery
  watchdog, wake/revoke ordering, and independent wait-slot,
  wake-continuation, and timer-credit conservation;
- its reject-enabled safety graph completed with 493,869 generated states,
  29,407 distinct states, zero queued states, and depth 20; the independent
  action/liveness graph completed with 5,192 generated states, 3,521 distinct
  states, zero queued states, depth 18, and seven temporal branches;
- the pure Rust successor passed 13 deterministic sequence tests and five
  proptests. Its target-local structure test closes `k=6` target effects with
  four index-head selections and six terminalizations while an unrelated
  `N=96` scope remains unchanged. The local `BTreeSet` still costs `O(log k)`,
  so this is structural evidence only, not a production `O(k)` curve;
- the model word has no user-store transition, so the checkpoint does not prove
  lost-wakeup or memory ordering. Futex live/blocked/revoke indexes also remain
  local beside an empty embedded Stage 6A syscall registry, not a unified
  syscall/futex or cross-service registry.
- the independent OSTD slice uses one shared guest `VmSpace`, separate
  waiter/waker `UserContext`s, atomic user-word loads, one guest `xchg` store,
  real v1 page faults, and a fresh v2 task. Its `recover` trace explicitly
  adopts the queued wait, cancels the watchdog, freezes one wake, rejects old
  authority after `RevokeBegin`, and publishes each result once. Its `expire`
  trace lets the watchdog close an uncommitted wake, rejects the old commit
  without mutation, aborts both continuations without inventing a Linux errno,
  and returns all wait/wake/timer credits before `RevokeComplete`;
- the serial oracle pairs all 22 portal results with full before/after
  projections, requires the scheduler's first fallback selection to be task
  500, permits either legal waiter/waker completion order only inside the
  closure-to-PASS interval, and forbids duplicate publication, expire resume,
  timeout fabrication, and panic.

Stage 6B.1 remains bounded to one private key, one waiter, one waker,
`max_wake = 1`, and one CPU; it has no Linux timeout, lost-wakeup/SMP proof, or
unified syscall/futex registry. The separate Stage 6B.2 successor and retained
workload receipt below close the bounded futex core gate without widening this
predecessor model.

## Stage 6B.2 personality-local core receipts

This checkpoint is recorded as **bounded successor semantics Checked / OSTD
QEMU slices Observed**:

- the two-key requeue TLA+ successor completes a 4,786,581-generated /
  1,927,174-distinct safety graph at depth 27 and a 247,047 / 140,473 action
  graph at depth 23, with four temporal branches and six witnesses. The
  readiness graphs are 83,586 / 50,544 at depth 20 and 55,569 / 34,428 at depth
  19, with three temporal branches and eight witnesses. The exec graphs are
  361 / 253 at depth 15 and 182 / 137 at depth 14, with three temporal branches
  and six witnesses;
- the common safe-Rust personality registry owns authority/binding fencing,
  immutable descriptors, opaque handles, typed credits, blocked-task and
  scope/task/resource indexes, atomic batch commit/resource movement,
  publication acknowledgement, exact snapshot/rebind/adopt, and scope-local
  closure. Futex requeue, readiness, and exec remain domain refinements over
  that lifecycle rather than separate authority registries;
- the two-key futex successor preserves immutable origin and mutable current
  resource identity, atomically freezes disjoint wake/move sets, returns
  Linux's affected count, and forbids a fresh binding from skipping an
  unadopted old queue head. Its pure-Rust gate contributes eight deterministic
  tests and two proptests; the common registry contributes eleven plus one;
- the readiness successor covers generational sources/subscriptions, atomic
  sample-and-arm, LT/ET/ONESHOT, immutable delivery, a positive timer, and a
  single ready/timeout/revoke winner. The exec successor keeps staging private,
  requires explicit adoption after a pre-commit crash, and publishes a whole
  image atomically. Readiness contributes six deterministic tests and one
  proptest; exec contributes six deterministic tests and one proptest;
- the adapted Round 4 artifact fixes source, patch, adapted-source, and ELF
  digests; a host Linux oracle requires exact stdout. Pinned QEMU observes
  eight-page mmap, three clone tasks, four waits, FIFO two-key requeue with
  `woken=1`, `moved=1`, `affected=2`, three explicit recovery adoptions,
  failure-atomic old-binding rejection, one frozen receipt publication, both
  closure orderings, and empty final indexes/credits;
- the adapted Round 5 artifact changes only the obsolete regular-file epoll
  expectation. Pinned QEMU executes 23 syscalls covering pipe ET, pipe
  ONESHOT, socketpair LT, timeout-zero empties, and regular-file `EPERM`. A
  readiness companion separately adopts six effects across crash/rebind and
  observes ready/timeout/revoke winners plus quiescent closure;
- the dynamic slice performs real launcher `execve`, stages an ET_DYN main and
  ET_DYN interpreter with eight total `PT_LOAD` mappings, TLS/TCB and initial
  stack, then crashes before commit. Fresh v2 explicitly adopts eleven effects
  before one `ExecCommit` and lock-external `VmSpace` publication. Exact auxv,
  interpreter/main TLS, FS-base load/save, stdout, write/exit publication, and
  12/12 credit return are observed.

These are personality-local, single-CPU bounded receipts. They do not provide
general futex/epoll/dynamic-linker ABI, lost-wakeup or SMP evidence, runtime
filesystem/network, a scheduler/pager/personality/I/O registry, integrated
fault-matrix evaluation, `k/N` curves, or a final originality judgment.

## System-wide CSER composition receipt

This checkpoint is recorded as **bounded five-domain prototype complete /
Checked and Observed**:

- `CompositionCser` fixes one root authority over scheduler, pager,
  personality, readiness, and VirtIO domains while keeping authority, binding,
  and device generations distinct. Its separate finite safety and action gates
  each explore 1,236,504 generated / 965,051 distinct states at depth 31; the
  action gate checks six temporal branches, while four reachability gates cover
  exact closure, crash/adopt isolation, commit/abort split, and timeout/retry;
- the safe-Rust composition backbone owns immutable parent identity, typed
  credit delegation, local reverse indexes, a common commit/revoke gate,
  domain-local crash/rebind/adopt, globally sequenced closure receipts, and a
  retained committed VirtIO timeout tombstone;
- the single-CPU OSTD receipt coordinates existing scheduler, pager,
  personality, and readiness mechanisms through one bounded gate, freezes the
  exact participating cohort, closes only causal leaves, rejects stale child,
  commit, and receipt operations, separately rejects stale parent and target
  derivation envelopes, retries the VirtIO tombstone, and reaches final
  zero-live/zero-pending state with all five credits returned;
- `./x composition` consumes the OSTD serial log and the separate Stage 5B
  VirtIO kernel log. It requires the real `avail.idx`-Release commit, reset
  timeout, retained DMA owners, reset retry, generation fence, IOTLB completion,
  and release ordering as prerequisite component evidence. It does not equate
  the independent composition generation-3-to-4 envelope with Stage 5B request
  1 or its generation-1-to-2 lifecycle.

This does not run five production services or real VirtIO DMA in one boot. It
does not add runtime filesystem/network, an unbounded causal graph, SMP,
production capability transport, a parameterized system fault matrix, `k/N`
curves, overhead evaluation, or a final originality judgment.

## Current research assets

| Path | Status | Disposition |
| --- | --- | --- |
| `specs/cser/` | **KEEP** | Normative baseline, domain refinements, and five-domain composition TLA+/PlusCal models, TLC configurations, and property documentation. Extend before each vertical slice without rewriting earlier evidence baselines. |
| `crates/cser-model/` | **KEEP** | Executable, `no_std + alloc` baseline, domain successors, and system-composition semantics plus differential/concurrency oracles. |
| `experiments/ostd-cser-spike/` | **KEEP** | Reproducible evidence for OSTD API fit, scheduler/pager recovery, Linux pressure slices, and the bounded five-domain root composition receipt. It may later be superseded by a broader prototype, but must remain runnable until then. |
| `experiments/ostd-virtio-cser-spike/` | **KEEP** | MPL-2.0-bounded patched-OSTD experiment for mediated readonly VirtIO, fail-closed reset/IOTLB tombstones, and three-owner queued IOTLB closure. Preserve both the Stage 5A no-device boundary and Stage 5B real-device receipt. |
| `specs/oracles/` | **KEEP** | Non-normative, implementation-neutral regression questions extracted from the old system. |
| `tests/guest/linux/` | **KEEP** | Compatibility-pressure workload inputs. `linux-hello`, adapted Round 4 futex, adapted Round 5 epoll, and dynamic PIE have bounded observed receipts; runtime filesystem and network remain pending. Exact retained sources are provenance rather than automatic conformance oracles, so visible temporary adaptations correct obsolete futex and regular-file epoll expectations. These inputs do not define Nexus's research identity. |
| `VISION.md` | **KEEP** | Research question, exclusions, candidate contribution, and evidence threshold. |
| `ARCHITECTURE.md` | **KEEP** | OSTD boundary, minimal kernel mechanisms, user-service boundary, and failure semantics. |
| `REWORK.md` | **KEEP** | This migration/deletion ledger. Update it when a row changes state. |

## Root build and repository control

| Path | Status | Disposition |
| --- | --- | --- |
| `Cargo.toml` | **KEEP** | The root workspace contains only `crates/cser-model`; admit future prototype crates only when a vertical slice requires them. |
| root and isolated `Cargo.lock` files | **KEEP** | Commit the model, xtask, OSDK project, and generated OSDK Run-base graphs; runtime containers mount project locks read-only. |
| `.cargo/config.toml` | **KEEP** | Contains only the bare-metal target flags used by the root no-std model gate. |
| `Dockerfile`, `rust-toolchain.toml`, `x` | **KEEP** | Pinned environment and stable host-side entry point for all retained gates, including both isolated OSTD spikes. |
| `tools/xtask/` | **KEEP** | Isolated workflow crate for model, catalog, scenario, TLA+, and artifact gates. |
| `.github/workflows/ci.yml` | **KEEP** | Invokes the same Docker-backed `./x verify` path used locally. |
| `flake.nix`, `flake.lock`, `.envrc` | **DELETE** | Removed in Phase 0; Docker is the environment boundary. |
| `justfile` | **DELETE** | Retained commands moved to `./x`/xtask; obsolete Axle and Starnix targets were not reproduced. |
| `.gitignore`, `.dockerignore` | **KEEP** | Cover only current Cargo, OSDK, QEMU, verification, and local-agent outputs. |
| `LICENSE` | **KEEP** | Keep the repository license while documenting third-party licenses, including OSTD's MPL-2.0 boundary. |

## Shared crates

| Module | Status | Disposition |
| --- | --- | --- |
| `crates/axle-arch-x86_64` | **DELETE** | Legacy userspace syscall/debug glue; OSTD owns the architecture boundary. |
| `crates/axle-core` | **MIGRATE** | Extract wait single-winner, stale-registration, deferred-revocation, and reverse-index race questions into neutral oracles; then delete the implementation. It is not CSER. |
| `crates/axle-mm` | **MIGRATE** | Retain same-page-fault contention and resource-accounting questions only. OSTD `VmSpace` and the new pager protocol replace the implementation. |
| `crates/axle-page-table` | **DELETE** | OSTD owns page-table traversal and mutation; do not maintain a second page-table stack. |
| `crates/axle-sync` | **MIGRATE** | Move relevant single-terminalization/Loom schedules into CSER concurrency tests, then delete this generic legacy crate. |
| `crates/axle-virtio-transport` | **MIGRATE** | Preserve queue bring-up and interrupt failure questions, not this synthetic transport. The mediated device path will wrap `virtio-drivers` and own CSER/DMA lifetime semantics. |
| `crates/axle-types` | **DELETE** | Remove the Axle UAPI and frozen Zircon aliases. New native interfaces use Nexus names; Linux UAPI comes from maintained upstream crates. |
| `crates/libax` | **DELETE** | Legacy native facade tied to the old syscall ABI. |
| `crates/libzircon` | **DELETE** | Remove all `zx_*` compatibility wrappers. |
| `crates/nexus-component` | **DELETE** | The old Fuchsia-shaped component IR is outside the CSER research core. Reintroduce a smaller service-launch format only if a concrete slice requires it. |
| `crates/nexus-fs-proto` | **DELETE** | Old filesystem wire protocol is not a retained kernel boundary. |
| `crates/nexus-fs-model` | **DELETE** | The DataFS preparation model is unrelated to the first CSER prototype; later storage work starts from the mediated-I/O contract. |
| `crates/nexus-io` | **DELETE** | Old fd/namespace substrate is coupled to `libax` and the old component tree. |
| `crates/nexus-rt` | **MIGRATE** | Extract only wait/timer/reactor cancellation cases. Rewrite any future userspace runtime against CSER tokens and the new native ABI. |

## Kernel

| Module | Status | Disposition |
| --- | --- | --- |
| `kernel/axle-kernel` | **REWRITE** | Replace as a whole with the OSTD-based Nexus prototype. No legacy kernel module is linked into the new kernel. |
| `arch/`, boot, SMP, traps, allocator, PMM | **DELETE** | Reuse OSTD boot/SMP/trap/frame/heap mechanisms. Keep only externally observed failure cases where named below. |
| `task/scheduler/` | **MIGRATE** | Preserve scheduler wake/fallback observations; the completed OSTD slice replaces the implementation. |
| `task/fault.rs`, VM fault paths | **MIGRATE** | Same-page contention and blocked-fault recovery questions were preserved in the pager refinement and bounded OSTD slice. The new mechanism is built around Nexus-gated one-shot fault continuations; no legacy VM code is retained. |
| `wait.rs`, `time.rs`, futex/wait state | **MIGRATE** | Preserve timeout/wake/cancel schedules; implement future waits as CSER-scoped effects over OSTD primitives. |
| `object/revocation.rs` | **MIGRATE** | Preserve stale deferred-state test cases only. Capability epoch invalidation by itself is not the new revocation mechanism. |
| `object/device.rs`, DMA objects, old PCI exports | **MIGRATE** | Preserve interrupt, queue, pin-budget, and fail-closed questions. Rewrite device mediation and real IOMMU quiescence. The old identity-IOVA path is not reusable evidence of closure. |
| channel/socket/object/handle implementation | **DELETE** | Zircon-shaped object semantics are not a research goal. Reintroduce only minimal native IPC required by a vertical slice. |
| old syscall dispatcher and generated Axle ABI | **DELETE** | Define a small native Nexus ABI; do not preserve syscall numbers for compatibility. |
| legacy trace implementation | **MIGRATE** | Retain measurement categories and artifact discipline. Current CSER traces already carry scope/effect IDs, both epochs, transitions, and results; migrate only useful legacy measurements into that schema, then add sequence and latency fields for failure and `k`-scaling reports. |

## Userspace and guest programs

| Module | Status | Disposition |
| --- | --- | --- |
| `user/nexus-init` root/component orchestration | **DELETE** | Remove the old component manager, resolver, namespace, asset embedding, and Fuchsia-shaped lifecycle. |
| `user/nexus-init/src/starnix` | **REWRITE** | Stage 6A now provides one new, bounded Linux-personality slice under the OSTD experiment; expand that compatibility server without copying the old guest-session/sidecar/stop-packet implementation. |
| `user/nexus-init/src/starnix/tests` | **MIGRATE** | Convert coverage intent into `tests/guest/linux/COMPATIBILITY.toml`; do not retain host tests coupled to old internal objects. |
| `user/nexus-init` network and remote-shell code | **DELETE** | Rebuild later over mediated VirtIO and a reused userspace network stack. |
| `user/test-runner` | **MIGRATE** | Extract only selected race/slice observations and neutral serial assertions, then delete the fixed-VA/libzircon runner. |
| `user/echo-client`, `user/echo-provider`, `user/controller-worker` | **DELETE** | Old component-routing smoke binaries have no unique CSER evidence. |
| `user/linux-*` C/assembly inputs | **MIGRATE** | Exact source copies live under `tests/guest/linux/sources/`; delete the old locations when the new build owns them. |
| externally supplied musl/glibc/BusyBox artifacts | **REWRITE** | Build pinned guest artifacts in Docker. Do not copy host runtime libraries opportunistically. |

## Host tools

| Module | Status | Disposition |
| --- | --- | --- |
| `tools/axle-conformance` | **MIGRATE** | Timeout, ordered/required/forbidden serial assertions, numeric bounds, bounded artifacts, and process cleanup were reimplemented in xtask. Axle-specific selection and retry machinery was not retained; add a smaller form only when multiple live scenarios require it. |
| `tools/axle-concurrency` | **MIGRATE** | Preserve the schedule ideas in `specs/oracles/cser-races.toml`; rewrite execution against the CSER core and later Loom/Kani harnesses. |
| `tools/syscalls-gen` | **DELETE** | Do not regenerate the obsolete Axle/Zircon ABI. Linux constants come from maintained UAPI crates. |
| `tools/nexus-manifestc` | **DELETE** | Coupled to the old component model. |
| `tools/datafs-check` | **DELETE** | Coupled to the deferred DataFS model. |
| old performance parsing scripts | **DELETE** | There is no tracked baseline to preserve. Build the `k`-scaling and failure-latency reports from the new CSER trace schema. |
| `syscalls/spec/`, `syscalls/generated/` | **DELETE** | Remove the old Axle syscall catalog and generated number table with `tools/syscalls-gen`; neither is a compatibility surface. |

## Specifications and tests

| Module | Status | Disposition |
| --- | --- | --- |
| `specs/conformance/contracts.toml` | **MIGRATE** | Extract only CSER-relevant race questions and Linux workload coverage. Delete Zircon MUST/SHOULD catalog semantics. |
| wait/timer/revocation/fault scenarios | **MIGRATE** | Distill into `cser-races.toml` and `legacy-slices.toml`; old commands must not survive because they build deleted crates. |
| device/net/page-loan scenarios | **MIGRATE** | Distill interrupt, queue, pinned-credit, and recovery observations. They do not prove real DMA quiescence. |
| `starnix_*` scenarios | **MIGRATE** | Preserve compatibility coverage and guest inputs in the Linux test matrix; remove the Starnix name from the future harness. |
| remaining channel/socket/eventpair/job/VMAR/VMO scenarios | **DELETE** | Keep Git history. Add a new native contract only when a CSER slice needs that behavior. |
| `specs/conformance/runner/*.S` | **DELETE** | These exercise the obsolete native ABI and are not Linux guest inputs. |

## Documentation

| Module | Status | Disposition |
| --- | --- | --- |
| `references/*.md` | **DELETE** | These describe the current Axle implementation. Git history is sufficient once the three top-level documents are in place. |
| `docs/TODO.md` | **DELETE** | Old roadmap and Starnix completion plan. |
| `docs/futex_semantics.md` | **DELETE** | Zircon-shaped futex divergence is not a future contract. Linux futex behavior belongs to the bounded personality test plan. |
| `docs/vm_cortenmm_adaptation.md` | **DELETE** | Describes the legacy custom VM implementation rather than the OSTD/pager architecture. |

## Intended end state

After deletion, the repository should visibly center on:

```text
VISION.md
ARCHITECTURE.md
REWORK.md
specs/cser/
specs/oracles/
crates/cser-model/
kernel/ or prototype/        # OSTD-based implementation only
tests/guest/linux/
tools/xtask/
Dockerfile / docker/
./x
```

Pager, mediated VirtIO, and Linux compatibility are admitted only through this
new structure. Passing an old scenario is useful evidence; inheriting an old
architecture is not.
