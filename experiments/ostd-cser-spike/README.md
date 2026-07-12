# OSTD/OSDK 0.18 CSER spike

This experiment answers a bounded sequence of architecture questions without
modifying OSTD 0.18: scheduler fallback; one-shot pager crash/rebind; a static
Linux syscall-personality path; private-futex recovery; and, in Stage 6B.2, a
personality-local common effect registry refined by two-key futex requeue,
generational readiness/epoll, and failure-atomic dynamic-PIE exec. It is
deliberately outside the deleted legacy Nexus workspace. The common registry
does not yet include scheduler, pager, or mediated VirtIO effects.

## Pinned environment

- OSTD: `=0.18.0` from crates.io
- cargo-osdk: `=0.18.0`
- `object`: `=0.39.1` for the bounded kernel ELF loader
- `linux-raw-sys`: `=0.12.1` for Linux UAPI names in the kernel and the
  independent freestanding personality workspace
- cargo-osdk 0.18.0 crate SHA-256:
  `726c0c05c18c46b783bd86060f775560609a0bf4696bd0cc2d8f265d59aa3764`
- Rust: `nightly-2026-04-03`
- Official OSDK image: `asterinas/osdk:0.18.0-20260603`, pinned to the amd64
  manifest digest in `Dockerfile`
- Upstream source tag: `v0.18.0`, commit
  `253be4750d69810af7b7b020fe2fee40a8547e15`

The dependency keeps OSTD's default `cvm_guest` feature. In 0.18.0, the x86
crate does not compile with that feature disabled because `arch/x86/io` and
`io/io_mem` retain unconditional references to feature-gated CVM items.
The boot scheme follows cargo-osdk's generated x86 kernel template: GRUB
Multiboot2 on OVMF. `qemu-direct` with the template's `q35` machine faults in
OSTD boot before `#[ostd::main]` and is not treated as a supported combination.

Build and run the complete probe:

```bash
./x test
```

The narrower commands are `./x check`, `./x build`, `./x run`, and
`./x iommu-probe`. The serial transcript is written to
`artifacts/serial.log`; `scripts/assert-serial.sh` verifies the scheduler,
pager, Stage 6A personality, both futex slices, readiness lifecycle, adapted
Round 5 epoll, and fail-closed IOMMU receipts. It invokes strict Round 4 and
epoll parsers plus negative trace mutations. `assert-linux-dynamic.awk`
independently fixes the dynamic exec/adoption trace and rejects a duplicate
PASS, a fabricated second ExecCommit, or Snapshot/Ready reordering. Raw
scheduler ticks are diagnostic, not an acceptance bound.

### Reproducible OSDK runner graph

Cargo-OSDK 0.18 generates a separate `*-run-base` Cargo workspace for
`build` and `run`. Its CLI does not propagate `--locked` to that generated
workspace, so relying on a project `Cargo.lock` alone would still resolve the
runner's transitive dependencies to the newest compatible versions.

`osdk-runner-base/` is a reviewed snapshot derived from the Run base emitted
by the pinned `cargo-osdk 0.18.0` tool (and therefore follows that tool's
MPL-2.0 provenance). It contains the generated manifest, entry point, linker
scripts, and its own lockfile; trailing whitespace in the linker scripts is
normalized for the repository. Before every build, `./x` installs the
snapshot at the path Cargo-OSDK would generate. Cargo-OSDK reuses it only when
its generated manifest and entry point are identical; after both `build` and
`run`, `./x` requires the complete directory to remain byte-for-byte
unchanged. The Docker image performs the same check while priming the
dependency graph.

If an OSDK upgrade legitimately changes this workspace, regenerate the
snapshot with that pinned version, review the full diff (including dependency
versions and linker scripts), and update the image key inputs together. Do not
refresh only the lockfile or accept a `Locking ... packages to latest
compatible versions` build as reproducible evidence.

The development image may use the network only while it is built. Normal
checks run as the invoking host UID with the project lockfile mounted
read-only, Cargo offline mode enabled, and Docker networking disabled.

The Linux input is also reproducible inside that boundary. The build copies
the retained `tests/guest/linux/sources/linux-hello/hello.S` only into a
temporary directory, emits a fixed-name `linux-hello.o`, and links a static
x86-64 `ET_EXEC` without a build ID. `scripts/assert-linux-elf.sh` checks its
ELF class, endianness, machine, program headers, absence of `PT_INTERP`, W^X,
the retained source SHA-256
`50690500a3cfac0f412da66d3d5d7f32b9b4da2a96a38d6d21c3ef12ea141490`,
and the container-built artifact SHA-256
`1dae72e6d4a5c9144e94580a8e2a8280cb36f725d66046baed77562051b2f1a4`.

The same build boundary fixes the Stage 6B.2 artifacts:

- adapted Round 4 futex ELF
  `c31cfc57e562e5be0e9558e5017a579b4353a016898113b07cbb467d31a2b7ca`;
- adapted Round 5 epoll ELF
  `1ff6f21480064d8ec84a8e58bef60c54733707fd13b1b2e46ab856daad8fc3f7`;
- retained dynamic launcher/main/interpreter sources, whose ELF layout,
  `PT_INTERP`, `PT_TLS`, load counts, W^X, and deterministic build products are
  checked by `assert-dynamic-pie-artifacts.sh`.

Round 4 and Round 5 patches apply only to temporary copies and have their
source, patch, and adapted-source SHA-256 values checked before compilation.
`check-fsbase-api.sh` also fixes the public OSTD `FsBase::load/save` API used by
the bounded dynamic path.

## What is exercised

1. `CserScheduler` is injected through OSTD's public `Scheduler` and
   `LocalRunQueue` traits before any task is run.
2. A bootstrap proposal bound to `(authority_epoch=41, binding_epoch=1)`
   selects the user-mode policy task at `Commit`, the scheduling decision's
   linearization point.
3. The policy task activates a real `VmSpace`. Its x86 program returns via
   `UserSyscall` to submit a heartbeat/proposal, then via
   `UserException(CpuException::PageFault)` to model a real policy crash.
4. `Crash` immediately advances the binding epoch from 1 to 2 and closes the
   proposal gate. Task exit drives OSTD's scheduler path to `FallbackPick`; the
   first fallback selection attempt must pick the expected FIFO task. The raw
   timer delta is recorded only as a diagnostic. A 64-tick lease remains as the
   compiled stalled-policy fallback, but this run does not separately trigger
   that lease-expiry branch.
5. Before `Rebind`, even an epoch-2 proposal receives
   `REJECT_NO_SUPERVISOR`. Rebind attaches the replacement to epoch 2 without
   advancing it again, and a proposal from epoch 1 receives `REJECT_STALE`.
6. Thin wrappers around OSTD `Waiter`/`Waker` and `Jiffies` preserve an
   `EffectToken`; the wait pair is exercised at runtime.

### Pager crash/rebind slice

The pager probe runs while the scheduler remains in its kernel FIFO fallback;
the pager binding and pager fallback state are independent of the scheduler
binding and scheduler fallback policy. It exercises two scenarios:

- In `recover`, a client takes a real user-mode not-present read fault and
  blocks on a kernel-held continuation. Pager v1 prepares a kernel-owned zero
  frame and then takes its own real page fault. The crash advances only the
  pager binding epoch, closes the reply gate, and retains the prepared frame.
  A kernel predicate probe rejects the shape of a late v1 commit before VM
  mutation. A freshly constructed v2 task, `VmSpace`, and task-local `UserMode`
  exercise the experiment's boolean recovery-snapshot/ready handshake. Before
  `Rebind`, a kernel no-supervisor predicate probe rejects the current-binding
  commit shape. Rebind attaches v2 without a second epoch advance and returns
  the pager fallback to `Standby`; another kernel predicate probe rejects the
  old binding after rebind. V2 must explicitly `RecoverNext` and `Adopt` before
  it can map the retained frame into the client's address space. The kernel
  issues, dispatches, and synchronizes the local TLB flush, terminalizes the
  continuation once, and wakes the client outside the state lock. The unchanged
  fault RIP is retried and reads zero. The snapshot flag is an ordering witness,
  not serialized or reconstructed pager policy state, and the rejection probes
  are not replayed user-space capability messages.
- In `timeout`, no replacement pager is started. A kernel watchdog advances
  the authority epoch and first publishes only `Closing`: the reply gate is
  closed, the retained frame and waker are removed from shared state, cleanup
  is marked in flight, and the frame credit remains held. It then drops the
  frame outside the pager-state lock, publishes the single abort notification
  authorized by the `FaultPhase` gate, and immediately destroys the local waker
  object while the scope is still `Closing` and the credit is still held. Only a
  second locked transition may confirm both obligations, return the credit,
  clear the cleanup/wake markers, and publish `Revoked`; `RevokeComplete` is
  emitted after that transition. Thus `RevokeComplete` cannot precede either
  actual retained-resource cleanup or terminal wake publication. A client that
  is scheduled immediately after the wake waits for closure publication before
  announcing its cooperative exit.

The continuation's authoritative one-shot property is enforced by Nexus's
`FaultPhase`/terminalization gate, not by OSTD's `Waker`: OSTD permits a waiter
to be armed again after a wait consumes a wake. The serial oracle therefore
checks exactly one successful completion, exactly one timeout abort, and three
kernel predicate probes: post-crash stale, pre-rebind no-supervisor, and
post-rebind stale. It also forbids timeout commit/resume, panic, and unexpected
scheduler epoch advance.

This is evidence for API fit and the stated transitions, not a production
pager. It is single-CPU, uses one client and a zero-page mapping, and exercises
only a local TLB synchronization path. The fault-page address deliberately
shares an existing 2 MiB page-table region with the guest code; OSTD's public
map path can still `unwrap` if an intermediate page-table allocation runs out
of memory. The watchdog polls `Jiffies` rather than using a production timer.
OSTD exposes no arbitrary public task-kill/join primitive here, so pager v1
returns from its closure after the real fault and the aborted client exits
after it is woken. SMP shootdown, arbitrary pager policies, multi-client
recovery, swap/file-backed paging, and production multi-effect or cross-service
revocation remain outside this slice.

`./x` assembles the base scheduler probe, pager client/v1/v2, Linux scheduler
policy, Linux code-pager v1/v2, private-futex, Round 4, and dynamic-personality
programs under `guest/`. It also builds the independent freestanding Rust
linuxd v1/v2 workspace, extracts each `.text` payload, builds the retained
`linux-hello`, adapted Round 4, adapted Round 5, and retained dynamic PIE ELF
set before invoking OSDK. This intentionally avoids a kernel Cargo build script:
cargo-osdk 0.18 recognizes a kernel only when its package has exactly one Cargo
target, so adding `build.rs` makes kernel discovery fail.

### Stage 6A static Linux/personality slice

The Linux slice is one bounded pressure test, not a general Linux server. The
kernel uses `object 0.39.1` to reject non-ELF64, non-x86-64, non-`ET_EXEC`,
dynamic-interpreter, overlapping, non-congruent, out-of-range, W+X, or
non-executable-entry images. It publishes all non-entry load pages eagerly,
builds a 16-byte-aligned RW/NX initial stack with `argc/argv`, empty `envp`, and
the required bounded auxv, but deliberately leaves the executable entry page
absent. `AT_RANDOM` is a fixed test fixture, not secure entropy.

The resulting instruction-fetch fault (`PFEC=0x14`) creates effect 3 in
`(authority=91, scope=30)`. Code-pager v1 prepares the retained ELF image frame
and then suffers a real user page fault before PTE publication. Fresh v2 uses
the bounded snapshot/ready/rebind/recover/adopt handshake, publishes one RX PTE,
synchronizes the local TLB, terminalizes and wakes once, and resumes the same
RIP once. In the same boot, scheduler effect 0 is attached to a user-policy
proposal; the policy faults, the proposal is cleared, and guest task 400 must
be the first kernel FIFO fallback pick on the next fallback selection attempt.
The raw timer-tick delta remains a diagnostic rather than a real-time bound.
Write effect 1, exit effect 2, code-fault effect 3, and completion effect 4 are
distinct.

The guest traps only `write(1, fixed_buffer, 23)` and `exit_group(0)`. Linuxd v1
and v2 are separate freestanding Rust artifacts with separate fresh OSTD
`Task`/`VmSpace`/`UserMode` instances. The kernel portal supplies an immutable
syscall snapshot and no writable guest context. V1 copies the bounded payload
into kernel ownership and crosses `BackendCommit`, which publishes the serial
output once, then takes a real user page fault before guest reply. V2 performs
snapshot/ready/rebind/recover/adopt, receives `AlreadyCommitted` instead of
replaying the output, publishes one write reply/resume, explicitly prepares the
exit reply, and terminalizes the process without another guest user-mode entry.

The user programs also submit full-identity packets containing authority,
scope, effect, blocked task, operation, and binding. The receipt exercises
post-crash, pre-rebind, post-rebind, and post-adopt stale/no-supervisor cases;
wrong effect identity; an unknown opcode; duplicate adopt/backend/reply; an
exit commit before prepare; and a duplicate terminal exit. Each exercised
rejection emits a semantic before/after projection covering scope and recovery
state, both continuation tokens/phases, payload ownership and checksum,
delivery counts, all wakers, the live count, guest outcome, and closure ledger.
The serial gate requires every rejection projection to be identical.

Two companion scopes use the same `PersonalityScenario`, token validator, and
prepare/commit/reply/revoke/closure implementation:

- scope 31/effect 5 prepares a write, lets `RevokeBegin` win, rejects early
  completion plus later user backend/reply attempts, then kernel closure aborts
  and publishes one real OSTD wake before `RevokeComplete`;
- scope 32/effect 6 commits first, closes authority, rejects the same later user
  operations, then kernel closure drains the existing obligation without a
  second output and publishes one wake before completion.

Both waiters are consumed by the kernel harness, and both early completion
attempts return `NotQuiescent`. These scopes refine personality-local
commit/revoke ordering; they do not revoke the co-tagged scope 30 and do not
provide a unified scheduler/pager/personality/I/O reverse index.

The Stage 6A bounds remain substantial: one CPU, fixed enqueue order, one guest
process/thread, one lazy code page, one single-slot portal, and a fixed static
ELF. Most linuxd control flow is `global_asm!`; the kernel harness still performs
portal delivery, guest copy-in, and state transitions. The v1 delayed packet is
held by a bounded kernel queue, while code-pager stale replies remain predicate
probes. There is no timeout/tombstone for the personality, dynamic linking,
PIE/TLS, fd table, general futex/requeue or epoll support, filesystem, network,
SMP, or production opaque capability transport. Serial output is a test
backend, not mediated VirtIO.

### Stage 6B.1 bounded private-futex slice

The successor slice is independent from the Stage 6A syscall registry. Two raw
guest Tasks share one `VmSpace` and one private futex word while retaining
separate `UserContext`s. The waiter first proves mismatch-without-effect for
`FUTEX_WAIT_PRIVATE`, then the personality performs an atomic load and enqueues
the matching wait under a full authority/scope/effect/task/operation/address-
space/address/binding token. The waker performs one guest `xchg` store before
issuing `FUTEX_WAKE_PRIVATE`; kernel state, not user policy, selects and freezes
the queued waiter at `WakeCommit`.

The `recover` trace crashes personality v1 with a real page fault, advances the
binding epoch, starts a fresh v2 task and `VmSpace`, requires
snapshot/ready/rebind/recover/adopt, and cancels the cohort watchdog without
removing the adopted queued wait. After the wake commits, `RevokeBegin` closes
the old authority; a replayed commit is rejected without mutation, and the
kernel publishes exactly one waiter result and one waker count while draining
the committed obligation. The scheduler policy also crashes through a real
page fault, and task 500 must be the first kernel fallback selection attempt.

The `expire` trace captures but deliberately does not commit the wake before v1
faults. Watchdog expiry closes authority, rejects the old wake token without
mutation, terminalizes both continuations as `Aborted`, wakes only the kernel
runners for cooperative exit, and returns wait/wake/timer credits before
`RevokeComplete`. It never resumes either guest `UserMode` and never fabricates
`ETIMEDOUT` or `ECANCELED`.

`scripts/assert-linux-futex.awk` pairs the exact 22 portal receipts with their
immediately following full-state projections. The surrounding serial oracle
checks exact closure/publication counts and permits either scheduler-dependent
waiter/waker completion order only between quiescent closure and scenario
PASS. This records Stage 6B.1 as **semantics complete and bounded OSTD/QEMU
slice complete / Observed**.

This predecessor is not a general futex implementation or execution of the
retained Round 4 workload. It is bounded to one private key, one waiter, one waker,
`max_wake = 1`, a null Linux timeout, and one CPU. It has no two-key requeue,
clone/mmap/thread-exit plumbing, lost-wakeup/SMP proof, or unified
syscall/futex registry. Stage 6B.2 supplies a separate successor and retained
workload receipt below; it does not retroactively widen the 6B.1 model.

### Stage 6B.2 common personality registry and futex core

The common registry owns immutable six-argument syscall descriptors, opaque
portal handles, authority and binding gates, typed renewable credits,
scope/task/resource reverse indexes, failure-atomic batch commit and resource
move, publication acknowledgement, restart snapshots, explicit adoption, and
scope-local revoke closure. Futex policy retains its FIFO queues and private
two-key identity, but A-to-B migration updates both the typed futex index and
generic current-resource membership under one runtime lock. This is shared
inside the Linux personality successor only. A committed pre-crash receipt may
also be completed by the kernel without a replacement: terminalization removes
it from the remaining recovery cohort, invalidates a previously issued Ready
proof, and retains its credit until the one publication acknowledgement.

The exact adapted Round 4 ELF runs with eight anonymous pages and three clone
tasks sharing one `VmSpace`. Four waits enqueue FIFO; one
`FUTEX_REQUEUE_PRIVATE` freezes `woken=1`, `moved=1`, and Linux affected count
`2`. Personality v1 then crashes with that receipt committed. Snapshot/ready/
rebind and three explicit adoptions recover the committed controller, the
moved waiter, and the remaining waiter without changing the receipt or queue
history. A replay from the old binding is rejected without changing the full
projection; kernel publication consumes the frozen receipt once, the target
wake reaches the migrated waiter, and exact stdout is `round4 futex ok\n`.
Commit-before-close and close-before-commit companions respectively drain two
and abort one, or abort all three without a partial resource move. The strict
oracle also rejects duplicate terminal evidence, a false affected count, and a
stale-call mutation claim. Final queues, effects, tasks, publications, and
credits are empty/free.

This bounded receipt is one CPU with fixed scheduling. It does not implement
Linux futex timeouts, signals, shared/PI/robust futexes, unmap invalidation,
bucket-lock SMP ordering, or a lost-wakeup proof.

### Stage 6B.2 readiness and adapted Round 5 epoll

The kernel-owned readiness core gives sources, sets, and subscriptions
generational identity; samples and arms atomically; records source masks and
sequences; and freezes immutable LT, ET, or ONESHOT delivery receipts. `MOD`
advances subscription generation, and stale source/service/subscription calls
cannot mutate state. The lifecycle companion recovers six effects through
snapshot/rebind/explicit adoption, publishes one pre-crash frozen delivery
once, and exercises ready-versus-timeout, timeout-versus-ready, and
revoke-versus-ready winners. It also proves that source/queue mutation
invalidates both a captured snapshot and an already issued Ready proof, and
that the new binding cannot select a queued old-binding subscription before
explicit adoption. A positive timeout registers its wait and timer in one
batch. Three publication acknowledgements precede final empty indexes and
returned credits.

The adapted retained Round 5 ELF executes 23 syscalls. Its exact trace covers
pipe ET, pipe ONESHOT, socketpair LT, timeout-zero empty results, and Linux's
regular-file `epoll_ctl(ADD) -> EPERM`; it prints exactly `round5 epoll ok\n`.
The adaptation changes only the obsolete regular-file expectation. Opening the
fixed `/bin/linux-hello` artifact does not constitute a runtime-filesystem
implementation. The result is not general fd/epoll, asynchronous interrupt,
SMP, filesystem, or network readiness.

### Stage 6B.2 failure-atomic dynamic PIE exec

A fixed ET_EXEC launcher really traps `execve`, after which the bounded loader
validates and stages an ET_DYN main plus ET_DYN interpreter at deterministic
biases. Each image contributes four W^X `PT_LOAD` mappings; the transaction
also stages variant-II TLS/TCB and a Linux initial stack with richer auxv.
Before commit, personality v1 takes a real fault. Fresh v2 must complete
snapshot/ready/rebind and explicitly adopt the exec transaction, eight load
mappings, TLS, and stack—eleven effects—before one atomic `ExecCommit`.
Only then is the new `VmSpace` published outside the registry lock; the old
launcher image becomes unreachable. Old handles submitted before and after
commit are rejected with an unchanged registry, staging, and image projection.

The interpreter checks its own and the main image's TLS and hands off to the
main, which prints exactly `dynamic pie ok\n`; write and exit publications are
acknowledged once and all 12 credits return. OSTD's public `FsBase::load/save`
is invoked around each `UserMode::execute`, but `UserContext` does not own FS
base. This observation is therefore limited to one CPU and one TLS-bearing
task. It is not a general relocation engine, runtime linker, shared-library or
libc path, multi-task TLS lifecycle, or filesystem-backed loader.

Together these are Stage 6B.2 personality-local bounded receipts. They do not
complete runtime filesystem, runtime network, cross-service scope unification,
SMP concurrency validation, or the final CSER contribution judgment.

## IOMMU result: fail closed

OSTD 0.18's `src/mm/dma/util.rs::unmap_dma_remap` removes second-stage page
table entries without a synchronous IOTLB flush. It deliberately does not
free the device-address range (there is a TODO preventing IOVA reuse), but
`unprepare_dma` then lets the DMA object's backing physical frames continue
through destruction and eventual reuse. A stale IOTLB entry can therefore
retain access to repurposed physical memory. The source itself contains:

```text
FIXME: Flush IOTLBs to prevent any future DMA access to the frames.
```

The invalidation machinery is under crate-private `arch::iommu`; an external
Nexus adapter cannot safely share its VT-d queue/domain state. The existing
register fallback writes `iotlb_invalidate` but does not wait for IVT to clear;
the queued-invalidation descriptor module only implements interrupt-cache and
wait descriptors, not an IOTLB descriptor. Reimplementing VT-d invalidation
beside OSTD would create two owners and is not a minimal adapter. Therefore
`Ostd018FailClosed::unmap_invalidate_and_wait` always returns
`IotlbInvalidationUnavailable`, and the spike never reports DMA quiescence.
`./x iommu-probe` checks these upstream facts against the fetched, pinned
source; the kernel also compiles and runs the fail-closed path. Device-level
drain/reset must precede even a future synchronous IOTLB invalidation adapter.

This unmodified-OSTD spike therefore cannot claim DMA-backed revocation
closure. The separate Stage 5B experiment chose a small, audited OSTD patch and
established only the bounded emulator receipt documented in the root
architecture. A production Nexus must still upstream a public synchronous
unmap+IOTLB-invalidate API, carry an audited patch, or reject OSTD as the DMA
ownership layer; this fail-closed adapter must never be treated as quiescence.
