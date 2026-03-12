# 90 - conformance

Part of the Axle test and contract layer.

See also:
- `Axle_v0.3.md` - engineering and gate expectations
- `10_ARCH_X86_64_STARTUP.md` - startup path exercised by QEMU scenarios
- `11_SYSCALL_DISPATCH.md` - syscall surface under test
- `12_WAIT_SIGNAL_PORT_TIMER.md` - many early MUST contracts live here
- `30_PROCESS_THREAD.md` - process/thread scenarios
- `33_IPC.md` - IPC scenarios and contract coverage
- `34_IPC_CHANNEL.md` - channel-specific scenario surface
- `35_IPC_SOCKET.md` - socket-specific scenario surface
- `40_VM.md` - VM scenarios and contract coverage

## Scope

This file describes the current host-test, fuzz, loom, and QEMU conformance structure in the repository.

## Test layers

The repository currently uses several layers:

- host unit tests for core crates
- loom tests for concurrency-sensitive code
- fuzz smoke for state-machine-heavy subsystems
- host-side concurrent seed replay and triage for schedule-sensitive subsystem boundaries
- QEMU conformance scenarios for syscall and early-kernel behavior

## Current command entry points

Main just targets include:

- `just fmt-check`
- `just xlint`
- `just xtest`
- `just loom`
- `just fuzz-smoke`
- `just concurrency-smoke`
- `just test-kernel`
- `just check-conformance-contracts`
- `just test-all`

## Contract catalog

- Contract definitions live in `specs/conformance/contracts.toml`.
- Scenarios declare which contract ids they cover.
- Every MUST contract now also carries explicit concurrent-harness metadata:
  - either `mode = "seeded"` with `system`, `hook_classes`, `state_projections`, and
    `expected_failure_kinds`
  - or `mode = "not_applicable"` with a reason when the current host-side concurrent harness does
    not model that contract
- `tools/axle-conformance` checks:
  - unknown contract references
  - uncovered MUST contracts
  - missing / malformed MUST concurrency metadata
- Current MUST gates now include core `wait_async`, `port`, `channel`, and same-page fault serialization contracts in addition to the earlier syscall/handle/timer/SMP basics.
- Bootstrap channel coverage now also includes one fragmented mixed-payload gate:
  - one exact-body remap read shape
  - one fallback-copy read shape
- Bootstrap channel coverage now also includes one async-signal gate:
  - `CHANNEL_WRITABLE` recovery through `wait_async` + `port_wait`
  - `CHANNEL_PEER_CLOSED` delivery through the same path without stale writable republish
- Bootstrap userspace runtime coverage now also includes one Phase-3 gate:
  - Rust ring3 code using `libzircon` can drive channel, socket, timer, port, and handle-close syscalls without handwritten per-syscall assembly
  - `nexus-rt` now exercises a single-thread dispatcher/executor shape:
    - generation-safe signal registration ids
    - one dispatcher timer instead of one kernel timer per sleep future
    - task wakeups routed through user packets on the dispatcher port
    - async channel receive/call and socket readiness paths
- Component-framework bootstrap coverage now also includes one eager-topology gate:
  - a minimal `nexus-init` can resolve a root manifest and launch eager ELF children
  - one protocol route through `/svc` is exercised end-to-end
  - child `OnTerminated` controller events are observed back in the manager
- The round-three component gate extends that with lazy lifecycle coverage:
  - one provider is lazy-started on first routed `/svc` open
  - `Stop` / `Kill` controller requests are exercised through the minimal component-manager path
  - `OnTerminated` controller events, not raw task-handle waits, are the lifecycle contract at this layer
- The Round-1 Starnix bootstrap scenario also runs under `-smp 2` and now acts as one regression
  guard for the scheduler's first-run child-launch path:
  - a brand-new child thread must not be opportunistically migrated to an unrelated idle AP before
    its first runnable handoff has respected its preferred / creator CPU
  - the scenario explicitly forbids a kernel `#GP` during that launch path
- The first Round-2 Starnix fd scenario now extends that same bootstrap path with one narrow
  Linux-fd slice:
  - `read` / `write` / `close`
  - `pipe2`
  - `socketpair(AF_UNIX, SOCK_STREAM)`
  - the guest path relies on the generic guest-session memory read/write helpers rather than on a
    Linux-specific kernel syscall mode
- The comprehensive Round-2 Starnix bootstrap scenario now closes the intended single-process
  task/mm/fs/socket loop:
  - `openat` / `fstat` / `newfstatat` / `getdents64`
  - `brk`
  - anonymous `mmap` / `mprotect` / `munmap`
  - read-only file-backed `mmap` through `FdOps::as_vmo()` / `GetVmo`
  - the supervisor keeps one Linux-side `LinuxMm` / map-tree control plane while continuing to
    rely on Axle VMAR/VMO syscalls for the real mapping work
- The Round-3 Starnix bootstrap scenario now closes the minimal task/process loop:
  - `clone(CLONE_THREAD)`
  - `fork`
  - `execve`
  - `wait4`
  - zombie reap and reparent-to-root behavior
  - the guest still sees stable Linux task identity even when `execve` swaps the underlying Axle
    carrier process/thread resources
- VMAR lifecycle is now also a MUST gate for bootstrap VM/TLB semantics:
  - map / protect / unmap must remain stable at the syscall surface
  - the calling thread must observe the committed mapping / protection state on return
- The first post-bootstrap substrate push now also reserves MUST gate ids for:
  - per-CPU L0 scheduler wake and reschedule behavior
  - generic process launch
  - executable mappings
  - strict TLB visibility
  Some of these gates currently start with minimal QEMU scenario definitions and tighten as kernel-visible telemetry lands.

This makes contract coverage part of the repo workflow, not just informal documentation.

## Scenario model

- Scenario specs live under `specs/conformance/scenarios/`.
- They cover current bootstrap subsystems such as:
  - waits / ports / timers
  - channel behavior
  - fragmented channel payload remap/copy coverage
  - socket behavior
  - VMO / VMAR behavior
  - process / thread behavior
  - SMP smoke
  - VM fault contention and loan/COW paths

## Runner model

- `tools/axle-conformance` is the host-side runner and reporting tool.
- It supports running, listing, replaying, and garbage-collecting scenario runs.
- Results are written under `target/axle-conformance/`.
- Scenarios are now grouped by exact `command` vector before execution:
  - one command-group run can satisfy many scenario assertions
  - each run still emits per-scenario `result.json`
  - shared `stdout.log` / `stderr.log` and group-level result metadata now live under each run's
    `groups/` subtree
- Most kernel scenarios build the kernel plus the current userspace runner, boot QEMU, and treat the printed summary line as the stable observable contract.
- QEMU scenarios that boot `nexus-test-runner` now copy the built runner binary to one unique temp
  path per command-group attempt before launching QEMU.
  - this avoids cross-group contamination when the same Cargo target is rebuilt concurrently with
    different entrypoint or assembly payload environment variables
- The runtime/reactor bootstrap scenario is the first case where the userspace runner entrypoint itself is defined in Rust instead of a standalone hand-written `.S` payload.
- That scenario now asserts structured dispatcher metrics instead of relying only on process exit:
  - registration slot reuse with generation advance after cancel
  - channel receive and channel call/reply correctness
  - sleep completion through one dispatcher timer
  - socket readiness and follow-on read correctness
- The eager component-topology bootstrap scenario is the first case where the
  component gate boots a dedicated `nexus-init` / `ElfRunner` root manager
  instead of reusing `nexus-test-runner` as both harness and manager.
- That component gate now boots a dedicated `nexus-init` image plus separate
  `echo-provider`, `echo-client`, and `controller-worker` ELFs through QEMU
  loader slots, rather than having `nexus-test-runner` impersonate every role
  from one self image.
- The eager and lazy component scenarios now rebuild the same `nexus-init`
  binary with different root-manifest URLs via `NEXUS_INIT_ROOT_URL`; topology
  selection is no longer driven by a separate smoke-mode branch in the manager.
- Those component scenarios now also exercise the current bootstrap `/boot`
  asset tree indirectly:
  - the built-in boot resolver opens compiled manifests from `/boot/manifests`
  - `ElfRunner` opens `/boot/bin/*` objects and requests read-only executable VMOs
- Because those dedicated userspace binaries are still linked at the
  long-standing bootstrap userspace VA above 4 GiB, the component scenarios
  build them with `RUSTFLAGS='-C code-model=large'` instead of changing the
  whole `x86_64-unknown-none` target configuration.
- The component scenarios now use wider QEMU loader spacing than the first
  round-two version because the dedicated Rust ELFs outgrew the older 4 MiB
  gaps, and the kernel bootstrap PMM reserved floor now follows that loader
  span instead of assuming a fixed 32 MiB ceiling is always sufficient.
- The bootstrap code window above 4 GiB is wider than the early 32 KiB bring-up shape so the
  runtime dispatcher runner and its shared summary pages no longer overlap in the fixed mapping.
- Some bootstrap channel metrics currently come from a second structured summary line rather than
  the main `int80 conformance ok (...)` line.
  - the fragmented channel payload scenario uses this to report both remap-path and fallback-copy
    results without overloading the older monolithic line further
- `tools/axle-concurrency` is a host-side Snowcat-lite runner for concurrent seeds:
  - seeds carry both operation programs and schedule hints
  - replay metadata includes runner version, logical CPU count, flags, PRNG seed, and step budget
  - each replay now also records stable hook classes and state projections in addition to the older
    semantic edge strings and hashed state signatures
  - the corpus predictor now scores seeds by rare semantic edges, rare state signatures, failure kinds,
    hint richness, and short-program density
  - mutation now chooses parents from the top predicted retained seeds instead of simple round-robin reuse
  - the corpus keeps seeds when they add semantic edge coverage, state signatures, or failure kinds
  - retained seeds are written under `target/axle-concurrency/host-corpus/`
  - each smoke run also writes `contract-coverage.json` under the host corpus directory and prints:
    - uncovered contract -> hook-class bindings
    - uncovered contract -> state-projection bindings
    - uncovered contract -> expected-failure-kind bindings
  - retained seeds now first try a direct guest-side replay path:
    - `tools/axle-concurrency` generates a dedicated bootstrap userspace runner assembly payload for
      the seed and boots it in QEMU
  - if the direct guest path does not converge, QEMU triage currently falls back to the closest
    existing bootstrap conformance scenario bundle through `tools/axle-conformance`

## Concurrent seed model

- The current concurrent runner starts with:
  - `wait / port / timer`
  - `futex / fault`
  - `channel / handle`
- It does not fuzz raw bytes directly at the subsystem level.
- Instead, it mutates short two-actor programs plus schedule hints such as:
  - `YieldHere`
  - `PauseThread`
  - `DelayTimerFire`
  - `ForceRemoteWake`
- Hints are attached to stable semantic hook ids rather than source locations.

## State-signature model

- The concurrent runner keeps abstract state signatures in addition to semantic edge hits.
- Signatures intentionally exclude raw addresses, handle values, and object ids.
- Current signatures summarize things such as:
  - blocked waiter counts
  - port queue occupancy and readiness
  - timer signal summary
  - futex queue occupancy
  - fault in-flight leader/waiter shape
- This exists because concurrent failures often appear under the same code coverage but different abstract state.
- The contract layer now also tracks named state projections alongside these hashes so retained-seed
  coverage can be reported back against contract metadata instead of staying only in the seed corpus.

## In-kernel / ring3 bridge

There are currently two closely related early test paths:

- an older in-kernel `int80_conformance` bridge under `kernel/axle-kernel/src/bringup/`
- the newer `user/test-runner` ring3 path used by the kernel bootstrap runner

The current tree still carries some bootstrap testing infrastructure in both places because the system is in transition from early kernel-only checks to more normal ring3-driven conformance.

## Current limitations

- Conformance coverage is strongest for the current bootstrap syscall surface, not for future subsystem families that are still missing.
- Some bring-up tests still depend on special bootstrap userspace plumbing.
- Loom coverage now extends beyond `axle-sync` into:
  - host-side `axle-core` wait-core winner races (`wake/timeout/cancel/requeue`)
  - host-side `axle-mm` fault/loan accounting models
- `axle-core` port/observer lifecycle and backpressure are currently covered by host unit tests and
  QEMU conformance, not loom state-space exploration.
- A local Stage-3 timer-backend profile currently does not justify replacing the binary-heap
  deadline backend with a wheel:
  - `BinaryHeap` push/pop churn stayed in the tens-of-nanoseconds range in a synthetic host-side
    profile up through ~16K pending entries
  - current QEMU conformance workloads do not show timer-backend pressure large enough to justify a
    more complex wheel / hybrid design yet
- The concurrent runner is currently strongest on the host-side semantic models.
- QEMU replay now prefers direct guest-side seed execution by generating a dedicated bootstrap runner
  from each retained seed.
- The direct guest path is still intentionally conservative:
  - it is a seed-driven runner generator, not yet a general-purpose in-guest bytecode interpreter
  - some retained seeds still fall back to existing scenario bundles when the direct path does not
    converge
- It still does not cover the full in-kernel wait/fault orchestration path under the real trap /
  scheduler bridge.
- The test architecture is already useful and real, but it is not yet the final long-term system-test stack for NexusOS.
