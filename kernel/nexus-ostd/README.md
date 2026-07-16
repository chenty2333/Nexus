# Nexus OSTD kernel prototype

This directory is the formal OSTD/OSDK 0.18 kernel prototype for Nexus. It
retains the bounded evidence that originally established scheduler fallback,
one-shot pager crash/rebind, the Linux personality slices, and system-wide CSER
composition. Composition coordinates the existing domain-local mechanisms
through one root authority backbone; it does not replace them with one global
object registry.

The source tree separates mechanism from pressure-test code without changing
the crate-root module API:

- `src/cser/`: effect tokens, the common effect registry, and composition;
- `src/domains/`: scheduler, pager, and readiness domains;
- `src/personality/`: Linux compatibility and runtime pressure slices;
- `src/probes/`: bounded platform feasibility probes;
- `guest/`, `scripts/`, and `osdk-runner-base/`: retained external evidence
  and reproducible OSDK machinery.

## Pinned environment

- OSTD: `=0.18.0` from the crates.io archive with SHA-256
  `aa160b3c09e0471f85f76a069e327b3df0bc60d5191b2ce3a64cc15cd62038e1`
- canonical MPL-2.0 OSTD overlay: `patches/ostd-0.18.0-cser.patch`, SHA-256
  `296dd6033d77dc10d0ed90236f1f0dfb18d261ca6bc266ac5f15220f0db56bfe`
- virtio-drivers: `=0.13.0` from the crates.io archive with SHA-256
  `cfdc1c628cdd8ce7c3b9e65a8ed550d0338e9ef9f911e729666f1cce097de2f7`
- canonical MIT split-publication overlay:
  `patches/virtio-drivers-0.13.0-cser.patch`, SHA-256
  `7576d6810af8ff4a2d4cbcd0dc02373946031aa2e3f7ae0528b0127b5ea33762`
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

Build and run the complete prototype test:

```bash
./x test
```

The private backend also exposes `./x doctor`, `./x fmt`, `./x check`,
`./x clippy`, `./x build`, `./x run`, `./x iommu-probe`, and `./x clean`.
`check` is the non-QEMU static gate: it composes formatting, OSDK check, the
freestanding personality check, and Clippy with warnings denied. The narrower
`fmt` and `clippy` commands expose those checks independently.
The generated OSDK runner snapshot intentionally keeps its upstream byte
layout and remains byte-for-byte guarded by every build. The serial transcript is written to
`artifacts/serial.log`; `scripts/assert-serial.sh` verifies the scheduler,
pager, Stage 6A personality, both futex slices, readiness lifecycle, adapted
Round 5 epoll, runtime filesystem, runtime network, system composition, and
fail-closed IOMMU receipts. It invokes strict Round 4, epoll, filesystem,
network, and composition parsers plus negative trace/artifact mutations.
`assert-linux-dynamic.awk`
independently fixes the dynamic exec/adoption trace and rejects a duplicate
PASS, a fabricated second ExecCommit, or Snapshot/Ready reordering. Raw
scheduler ticks are diagnostic, not an acceptance bound.

After this prototype and the separate Stage 5B VirtIO experiment have both run, the
repository-root `./x run composition` command cross-checks `artifacts/serial.log`
against the Stage 5B `artifacts/kernel.log` guest receipts and
`artifacts/qemu-debug.log` device trace for component consistency. Root
`./x verify` reruns the Stage 5B split-stream oracle and then this composition
check automatically after both QEMU gates.

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
   `UserSyscall` to submit a heartbeat/proposal. An accepted proposal renews the
   64-tick lease under the run-queue lock after all reject gates and before the
   pending proposal becomes visible; rejected proposals never renew it. The
   policy then returns via
   `UserException(CpuException::PageFault)` to model a real policy crash.
4. `Crash` immediately advances the binding epoch from 1 to 2 and closes the
   proposal gate. Task exit drives OSTD's scheduler path to `FallbackPick`; the
   first fallback selection attempt must pick the expected FIFO task. The raw
   timer delta is recorded only as a diagnostic. The selection ordinal advances
   only after a non-empty FIFO pop; an empty-queue probe selects no task, emits
   no receipt, and consumes no hidden ordinal. A 64-tick lease remains as the
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
by themselves complete runtime filesystem, runtime network, cross-service
scope unification, SMP concurrency validation, or the final CSER contribution
judgment. The separate follow-on checkpoint below addresses only the bounded
composition item.

### Bounded runtime filesystem

The Stage 6 runtime-filesystem successor builds the unchanged retained
`runtime_fs_smoke.S` into a static x86-64 `ET_EXEC`. The fail-closed build fixes
source SHA
`c5a4014d88794ddccd1c5239957a43500a6637a433640c2293e699fea72b870f`
and artifact SHA
`0dc5ad40cb05e39592592ef3272ed45be4d71f9b147a534be20b9a5626c17bef`,
and rejects dynamic dependencies, relocations, executable stack, W+X, or source
and artifact mutation. The shared loader retains one-page stacks for existing
inputs and maps exactly two pages for this unchanged guest, whose entry reserves
4096 bytes below its initial stack pointer.

Pinned one-CPU QEMU executes exactly 14 Linux syscall invocations through real
OSTD `UserMode`: three `openat`, two `pread64`, `statx`, `newfstatat` with
`AT_EMPTY_PATH`, `pwrite64("xy", offset=2)`, relative
`readlinkat(proc-self-fd, "exe")`, three closes, exact stdout, and `exit(0)`.
The bounded service owns only an in-memory executable inode, one temporary inode,
and `/proc/self/exe`. Every continuation uses one workload-owned production
registry. For the first executable `pread64`, personality capture occurs before
fd resolution or payload access, then the same root receives immutable
`FilesystemSyscall -> FilesystemRead -> BlockRequest` ancestry. The filesystem
child survives a registry-domain crash injection, snapshot, Ready, rebind, and
explicit adoption. This is a bounded registry transition, not a real crashing
OSTD user service. Guest-memory output remains a later publication, and all 14
personality tickets are acknowledged before root closure.

The lifecycle companion has actual independent pager, filesystem, personality,
and block binding state. Prepared pager/filesystem effects require snapshot,
Ready, rebind, and explicit adoption; a committed reply can complete from its
immutable receipt while the personality is absent. Both pwrite/revoke orders and
every stale call compare the registry, effect, domain, inode, or block projection
for zero mutation. Separate reset and IOTLB tombstones retain three abstract
owners; timeout does not advance device generation, ResetAck advances it, and
only IOTLB Ack releases ownership.

Phase 2 stops at deterministic block preparation. It aborts that prepared
effect without a device commit and keeps queue-slot, pinned-page, and DMA credit
capacity free; the returned ELF bytes still come from the in-memory inode. The
host gate binds the guest, first-pread input, four-byte payload, and preparation
record by digest, and rejects a receipt from a fresh registry without mutation.

The primary boot has no real DMA. `tools/workflow/runtime-fs-composition.sh`
joins it to the independent real Stage 5B boot using those digests plus the
reconstructed sector SHA
`9cb83be92a4c9239752718e6e20ac00fe9e32842ea561ae7fedec94b620a05cc`,
sector FNV, and full readonly-image SHA
`27a4e8fed7b428b42ff04e3f62eadfe2e3f3310dac4e2fe8ecfff04be3cca254`.
This is `component_consistency`, with `same_boot=false` and no
identity-preserving Stage 5B device path; it is not a general or persistent
filesystem.

### Bounded runtime network

The Stage 6 runtime-network successor builds the unchanged retained
`runtime_net_smoke.S` into a static x86-64 `ET_EXEC`. The fail-closed build
fixes source SHA
`65ba020b526fe1cbf05feef0739791a3ae6274b2ffa2b39d385ce88e1a086ecf`
and artifact SHA
`8cdd5864c07e51e91d9e0a6ec94e4d7d6438db2fbb39d513bfb7c5624d32f549`,
and rejects source/artifact mutation, dynamic dependencies, relocations,
executable stack, W+X, or other ELF structural drift.

Its independent `RuntimeNetCser` counterpart checks 3,698,288 generated /
720,002 distinct states at depth 42 for safety and 28,449 / 14,328 at depth 35
for the action graph, with eight temporal branches and eight witnesses. The
safe-Rust oracle separately contributes ten deterministic, two property, and
four Loom gates over Control, Network, Readiness, and Buffer credits.

Pinned one-CPU QEMU executes exactly 22 Linux syscalls through real OSTD
`UserMode`. One bounded in-memory IPv4 loopback listener, client, and accepted
socket cover `socket`, options, bind/name/listen, connect/peer, accept, exact
four-byte ping/pong, `SHUT_WR`/EOF, three closes, exact stdout, and exit. The
common registry separates commit, guest-memory publication, acknowledgement,
kernel-owned readiness, and Buffer credit ownership.

A separate real OSTD `UserMode` netd-v1 completes the first nine network
operations, prepares accept, and takes a page fault before its commit. Netd-v2
performs snapshot/Ready/rebind, explicitly adopts the frozen accept and
readiness effects, rejects the stale v1 binding with the full state projection
unchanged, then commits accept and completes the remaining operations. Strict
positive and negative oracles bind the exact call/lifecycle order, source and
ELF digests, readiness/buffer witnesses, and limitation markers.

This is a bounded in-memory loopback, not smoltcp, real TCP breadth, external
packets, VirtIO-net, a NIC, multi-connection/backpressure behavior, or SMP. The
old composition receipt below remains frozen with `runtime_fs=false` and
`runtime_net=false`; the additive seven-domain Linux I/O successor consumes
this receipt only as an already-revoked same-boot prerequisite.

### Bounded system-wide CSER composition

The follow-on composition slice installs one root authority over five existing
domain adapters. Its fixed causal DAG is
`root -> personality -> pager -> scheduler` and
`personality -> readiness -> VirtIO`. Domain scope IDs are local reverse-index
keys, not nested authority scopes; authority epoch, per-domain binding epoch,
and VirtIO device generation remain independent.

One `CompositionBackbone` gate requires coordinator-owned exact target enrollment,
validates both the current parent and current target envelopes, and installs
every causal edge, domain token, typed-credit transfer, and local reverse-index
entry failure-atomically. Separate stale-parent and stale-target receipts must
leave the full state unchanged. Domain crash/rebind/adopt remains local: a
replacement cannot mutate peers or inherit an old effect implicitly. Root
`RevokeBegin` advances authority and freezes only the participating live
cohort. Closure is leaf-gated: scheduler closes before pager, and VirtIO closes
before readiness; personality cannot close until both branches have closed.
Globally sequenced receipts are issued and accepted through the same gate and
are bound to the current revoke/domain/generation envelope.

The committed VirtIO effect deliberately times out once. It and its typed
credit remain live behind a tombstone, so the root can report `TimedOut` only
while still `Closing`. Retry makes the old timeout receipt stale; reset plus
IOTLB acknowledgement permits a fresh `Closed` receipt, causal-ancestor
closure, complete credit return, and final `Revoked`. Stale child, commit, and
receipt attempts are required to leave the backbone unchanged.

The local VirtIO object is an `external_stage5b_consistency` adapter. Its
composition retry advances the domain closure revision and its independent
device generation from 3 to 4. The strict split-stream oracle separately
requires the real Stage 5B `avail.idx` Release, reset timeout, retained DMA
owners, retry, device-generation fence, IOTLB completion, and DMA-release trace
as prerequisite component evidence. Guest receipts and QEMU trace events keep
independent order and are joined only by stable owner IOVA/PADDR values; no
cross-FD temporal total order is claimed. Stage 5B instead completes request 1
in generation 1 and then fences generation 1 to 2; the evidence streams do not
share the composition effect, ticket, or generation identity. This is therefore
not an identity-preserving refinement or a same-boot claim about five
production services and real device DMA.

The receipt is one CPU with a fixed six-node/five-edge graph. This frozen
predecessor does not add runtime filesystem or network, SMP composition, a production opaque authority
transport, a parameterized fault matrix, `k/N` curves, overhead evaluation, or
a final originality judgment. The separate filesystem and network successors
above do not retroactively change its `runtime_fs=false` / `runtime_net=false`
receipt.

### Additive seven-domain Linux I/O composition

The additive companion creates a fresh root scope 120 at authority epoch 401;
it does not modify the five-domain receipt. One real `EffectRegistry` holds nine
fresh effects and nine credit units in eight classes across personality, pager,
scheduler, filesystem, VirtIO, network, and readiness. The coordinator records
the fixed two-branch causal graph and target-domain reverse indexes while
service binding and resource-generation dimensions remain honest bounded outer
envelopes around the registry's single root binding.

`FsOp` commits before a four-byte inode mutation, `BlockReq` commits at an
abstract `avail.idx` boundary, `NetOp + BufferLease` commit atomically through
`commit_with_moves`, and `ReadinessWait` requires the exact `NetOp` commit
receipt before using the real `ReadinessCore`. The two syscall-controller
effects remain uncommitted, so root closure aborts them without fabricating
filesystem or network replies.

`RevokeBegin` freezes all seven domains and nine effects. Closure selects the
fixed child-first order through the target-domain indexes. The committed VirtIO
effect first yields an honest `TimedOut` receipt while its effect and DMA credit
remain live; retry invalidates that receipt, advances only the bounded device
generation, and permits a new `Closed` receipt. Seven current Closed receipts,
one invalidated timeout, nine terminalizations, and all nine credits free are
required before final `Revoked`.

The runtime-filesystem and runtime-network workload receipts were already
revoked earlier in the same boot and carry no effect handle into scope 120.
Likewise Stage 5B remains a separate-boot component-consistency check. The
companion therefore claims neither retained-workload identity, registry-native
multi-domain bindings, real DMA in the primary boot, identity-preserving Stage
5B composition, TCP/VirtIO-net breadth, nor SMP.

### Stage 7B release evaluator

`./x eval-stage7b` builds the kernel with the isolated `stage7b-eval` feature
and a release profile, then runs only the evaluator. The runner fixes
`-smp 1 -accel tcg,thread=single`, pins the Docker/QEMU process to the first CPU
in the host's allowed CPU list, and records that pin beside the raw serial log.
The 20 fault cells exercise the shared scheduler, deadline, pager, one-shot,
registry, and I/O transition gates. The 14 scale points use the production
`EffectRegistry` fixture and require zero target-record visits at begin,
`next_calls = k + 1`, `head_selections = k`, one exact `k`-member completion
validation, and zero unrelated/history visits.

The evaluator retains 257 empty-timer samples and 65 raw samples for each of 29
operations. TSC reads are LFENCE-delimited with local IRQs and preemption
disabled only for the measured interval; fixture construction, clone, full
invariant reconstruction, and serial output stay outside. The host oracle
recomputes min, median, nearest-rank p95, and max. These data are Observed
guest-visible TSC results, not hardware cycles, thresholds, or a performance
superiority claim. Implementation-source Loom evidence remains separately
bounded to production transition source under a Loom-modeled outer mutex; it
does not verify OSTD `SpinLock`, SMP execution, lock freedom, or liveness.

## IOMMU result: patched build foundation, runtime still fail closed

Pristine OSTD 0.18's `src/mm/dma/util.rs::unmap_dma_remap` removes second-stage
page-table entries without a synchronous IOTLB flush. It deliberately does not
free the device-address range (there is a TODO preventing IOVA reuse), but
`unprepare_dma` then lets the DMA object's backing physical frames continue
through destruction and eventual reuse. A stale IOTLB entry can therefore
retain access to repurposed physical memory. The pristine source itself
contains:

```text
FIXME: Flush IOTLBs to prevent any future DMA access to the frames.
```

The primary kernel build now applies the repository-wide, hash-bound
`patches/ostd-0.18.0-cser.patch` to that exact archive. The same canonical
overlay is used by the Stage 5B experiment. It provides the ownership-carrying
DMA begin/poll closure API and a configurable GSI mapping API, including
I/O APIC polarity/trigger bits and a synchronized interrupt-remapping trigger
mode. The kernel build checks positive application, clean reverse application,
installed-source equivalence, and negative source mutations before compiling.

The same two build graphs reconstruct the exact virtio-drivers 0.13.0 archive
and apply the canonical MIT split-publication overlay. It provides a linear,
fail-closed prepared-queue owner, an infallible unique Release publication,
and exact-buffer cancellation. The optional production facade adds descriptive
hardware coordinates, failure-atomic identity preflight, and a prevalidated
infallible reset-generation plan without owning registry authority. IOTLB
quiescence uses the same prevalidate/direct-apply shape so the Registry can
couple acknowledgement and facade slot release.

The later bounded runtime-filesystem schemes now exercise that facade in the
primary kernel. After a real user-mode fsd-v1 page fault and a post-crash
fsd-v2 Task/VmSpace construction plus Registry recovery, the normal lane
enrolls one six-effect cohort, performs one same-boot VirtIO/IOMMU read, polls
its completion with INTx masked, retains the concrete owners across injected
reset and IOTLB Pending results, and releases them after acknowledgement. The
paired pre-commit lane prepares the same concrete owners but lets revoke win
before device publication. This is a one-vCPU, one-request vertical slice; it
does not map a real configured GSI, deliver an IRQ, cover every crash point, or
establish SMP/device breadth.

The generic `iommu_probe` adapter remains `Ostd018FailClosed`; its
`unmap_invalidate_and_wait` still returns `IotlbInvalidationUnavailable` rather
than claiming unsupported quiescence. That probe and the runtime-filesystem
facade are separate call sites. Device-level drain/reset continues to precede
the synchronous IOTLB completion consumed by the bounded facade path.

`./x iommu-probe` deliberately checks the fetched pristine archive, rather
than the patched build tree, so the upstream 0.18.0 gap remains explicit. The
separate Stage 5B experiment consumes the canonical patch and establishes only
its older component-consistency receipt. The newer runtime-filesystem schemes
provide the primary-kernel same-boot DMA observation described above; real IRQ
delivery/quiescence, 2/4-vCPU execution, and the remaining RFC fault matrix are
still unestablished.
